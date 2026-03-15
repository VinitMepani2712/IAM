import logging

from analysis.criticality import compute_node_criticality
from core.privilege_model import classify_action
from analysis.risk_model import compute_risk, classify_severity
from analysis.attack_patterns import classify_attack_pattern
from analysis.centrality import compute_escalation_centrality
from analysis.min_cut import compute_weighted_minimal_cut
from analysis.dominator import compute_dominators

from graph.attack_graph import build_attack_graph
from graph.reachability import find_all_escalation_paths

log = logging.getLogger(__name__)


# =========
# Full Environment Analysis (Web Safe)
# =========

def analyze_environment_data(principals):

    log.info("Starting environment analysis — %d principals", len(principals))
    graph = build_attack_graph(principals)
    log.debug("Attack graph built — %d nodes", len(graph.nodes))

    # ── Pre-compute which principals are reachable FROM other principals ──────
    # A principal is "an attacker entry point" if at least one OTHER principal
    # has a graph edge leading into it, OR if it is a user (users are always
    # potential entry points — they represent human actors).
    # Roles that nobody can assume (no incoming edges from other principals)
    # only generate findings if they expose a path that other principals will
    # use; but their OWN 2-hop direct-capability path (Role → CAPABILITY) is
    # not an escalation — nobody arrived there through an exploit.
    inbound_principals = set()   # principals that have at least one caller
    for src, neighbors in graph.adjacency.items():
        for dst in neighbors:
            if dst in principals:
                inbound_principals.add(dst)

    findings = []

    for principal_name, principal in principals.items():

        paths = find_all_escalation_paths(graph, principal_name)
        if not paths:
            continue

        # Capabilities the principal directly holds WITHOUT needing combinations.
        # We only skip FULL_ADMIN / ROLE_ASSUMPTION / PRIVILEGE_PROPAGATION
        # because those are broad "already elevated" states.
        # ACCESS_KEY_PERSISTENCE, CONSOLE_ACCESS, IDENTITY_CREATION, COMPUTE_LAUNCH,
        # and POLICY_MODIFICATION are always reported — they represent concrete
        # attack capabilities regardless of whether the principal "directly" has them.
        SKIP_IF_ALREADY_HELD = {"FULL_ADMIN", "ROLE_ASSUMPTION"}
        original_caps = set()
        for stmt in principal.policy_statements:
            if stmt.effect == "Allow":
                for action in stmt.actions:
                    cap = classify_action(action)
                    if cap and cap in SKIP_IF_ALREADY_HELD:
                        original_caps.add(cap)

        centrality = compute_escalation_centrality(paths)
        centrality_score = centrality.get(principal_name, 0)

        valid_paths = []

        for path in paths:

            capability_node = path[-1]
            if not capability_node.startswith("CAPABILITY::"):
                continue

            cap_class = capability_node.split("::")[1]

            # Skip only if this principal DIRECTLY holds this exact capability
            # via its own managed policy AND no other principal can chain into it
            # through an escalation path. We detect this as: path length == 2
            # (principal → CAPABILITY directly, no action/role hops) AND the
            # principal already has that capability classified from its actions.
            # We do NOT skip it if another principal could reach it through this
            # one (that case is handled when that other principal is analyzed).
            if len(path) == 2 and path[0] == principal_name and cap_class in original_caps:
                continue

            # For roles with no callers (orphan roles): skip direct 2-hop paths.
            # An orphan role holding AdministratorAccess is a configuration risk
            # but NOT an exploitable escalation path — no attacker can reach it.
            # It will still appear in findings when traversed FROM another principal.
            if (len(path) == 2 and path[0] == principal_name
                    and getattr(principal, "type", None) == "role"
                    and principal_name not in inbound_principals):
                continue

            # Skip if the principal already directly holds this capability
            if cap_class in original_caps:
                continue

            valid_paths.append(path)

            # -------------------------------------------------
            # Cross-account detection
            # -------------------------------------------------
            accounts = [
                principals[node].account_id
                for node in path
                if node in principals
            ]

            cross_account = len(set(accounts)) > 1

            # ── Condition key analysis ─────────────────────────────────────
            # Walk every role in the path and collect trust conditions that
            # apply to the step leading into that role.
            condition_flags = {
                "requires_mfa":         False,
                "requires_external_id": False,
                "condition_summary":    [],
            }
            for node in path:
                p_obj = principals.get(node)
                if not p_obj:
                    continue
                tc_map = getattr(p_obj, "trust_conditions", {}) or {}
                for trusted_arn, tc in tc_map.items():
                    if tc.requires_mfa:
                        condition_flags["requires_mfa"] = True
                        condition_flags["condition_summary"].append(
                            f"{node}: MFA required"
                        )
                    if tc.requires_external_id:
                        condition_flags["requires_external_id"] = True
                        eid_str = f" ({tc.external_id_value})" if tc.external_id_value else ""
                        condition_flags["condition_summary"].append(
                            f"{node}: ExternalId{eid_str} required"
                        )

            risk = compute_risk(
                capability_class=cap_class,
                path_length=len(path),
                centrality_score=centrality_score,
                cross_account=cross_account,
                requires_mfa=condition_flags["requires_mfa"],
                requires_external_id=condition_flags["requires_external_id"],
            )

            severity = classify_severity(risk)

            pattern_list = classify_attack_pattern(path, cross_account)
            primary_pattern = pattern_list[0]

            finding = {
                "principal":            principal_name,
                "account_id":           principal.account_id,
                "capability":           cap_class,
                "risk":                 risk,
                "severity":             severity,
                "cross_account":        cross_account,
                "path":                 path,
                "pattern":              primary_pattern["pattern"],
                "mitre":                primary_pattern["mitre"],
                "all_patterns":         pattern_list,
                "condition_flags":      condition_flags,
            }

            findings.append(finding)

        if valid_paths:
            compute_weighted_minimal_cut(valid_paths)
            compute_dominators(valid_paths)

    criticality = compute_node_criticality(findings)

    all_paths = [f["path"] for f in findings]

    if all_paths:
        minimul_cut = compute_weighted_minimal_cut(all_paths)
        dominators = compute_dominators(all_paths)
    else:
        minimul_cut = []
        dominators = {} 
    
    remediation_summary = {
        "total_paths": len(all_paths),
        "recommended_fixes": minimul_cut,
        "dominators": sorted(dominators) if dominators else []
    }

    log.info(
        "Analysis complete — %d findings (%d critical)",
        len(findings),
        sum(1 for f in findings if f.get("severity") == "CRITICAL"),
    )
    return findings, criticality, remediation_summary


# =========
# 📊 Extract Graph Data (with Cross-Account Visualization)
# =========

def extract_graph_data(graph, findings=None, escalation_only=False, root=None):

    nodes = []
    edges = []

    escalation_edges = set()
    cross_account_edges = set()
    escalation_nodes = set()

    # ---------------------------------
    # Collect Escalation + Cross-Account Metadata
    # ---------------------------------
    if findings:
        for f in findings:
            path = f.get("path", [])

            for i in range(len(path)):
                escalation_nodes.add(path[i])

                if i < len(path) - 1:
                    edge = (path[i], path[i + 1])
                    escalation_edges.add(edge)

                    # Detect cross-account transitions
                    src = path[i]
                    dst = path[i + 1]

                    # Cross-account detection
                    if f.get("cross_account"):
                        cross_account_edges.add(edge)

    # ---------------------------------
    # Build Nodes
    # ---------------------------------
    for node in graph.nodes:

        if escalation_only and node not in escalation_nodes:
            continue

        shape = "dot"
        color = "#3b82f6"
        label = node
        tooltip = f"Node: {node}"

        if node.startswith("CAPABILITY::"):
            shape = "star"
            color = "#22c55e"
            label = node.replace("CAPABILITY::", "")
            tooltip = f"High Impact Capability: {label}"

        nodes.append({
            "id": node,
            "label": label,
            "shape": shape,
            "color": color,
            "title": tooltip
        })

    # ---------------------------------
    # Build Edges
    # ---------------------------------
    for src, neighbors in graph.adjacency.items():

        for dst in neighbors:

            if escalation_only and (src, dst) not in escalation_edges:
                continue

            edge_color = "#64748b"
            width = 1
            dashes = False
            label = "Trust / Assume"

            # Escalation path
            if (src, dst) in escalation_edges:
                edge_color = "#facc15"
                width = 2
                label = "Escalation Path"

            # Cross-account escalation
            if (src, dst) in cross_account_edges:
                edge_color = "#ef4444"
                width = 3
                dashes = True
                label = "Cross-Account Pivot"

            edges.append({
                "from": src,
                "to": dst,
                "label": label,
                "color": edge_color,
                "width": width,
                "dashes": dashes,
                "arrows": "to"
            })

    return nodes, edges