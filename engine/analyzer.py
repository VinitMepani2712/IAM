from analysis.criticality import compute_node_criticality
from core.privilege_model import classify_action
from analysis.risk_model import compute_risk, classify_severity
from analysis.attack_patterns import classify_attack_pattern
from analysis.centrality import compute_escalation_centrality
from analysis.min_cut import compute_weighted_minimal_cut
from analysis.dominator import compute_dominators

from graph.attack_graph import build_attack_graph
from graph.reachability import find_all_escalation_paths


# ============================================================
# 🔎 Full Environment Analysis (Web Safe)
# ============================================================

def analyze_environment_data(principals):

    graph = build_attack_graph(principals)
    findings = []

    for principal_name, principal in principals.items():

        paths = find_all_escalation_paths(graph, principal_name)
        print(f"\nChecking principal: {principal_name}")
        print("Paths found:", paths)
        if not paths:
            continue

        original_caps = set()

        for stmt in principal.policy_statements:
            if stmt.effect == "Allow":
                for action in stmt.actions:
                    cap = classify_action(action)
                    if cap:
                        original_caps.add(cap)

        centrality = compute_escalation_centrality(paths)
        centrality_score = centrality.get(principal_name, 0)

        valid_paths = []

        for path in paths:

            capability_node = path[-1]
            if not capability_node.startswith("CAPABILITY::"):
                continue

            cap_class = capability_node.split("::")[1]

            # Only skip if the user already has FULL ADMIN directly
            if cap_class == "ADMINISTRATOR_ACCESS" and cap_class in original_caps:
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

            risk = compute_risk(
                capability_class=cap_class,
                path_length=len(path),
                centrality_score=centrality_score,
                cross_account=cross_account
            )

            severity = classify_severity(risk)

            pattern_list = classify_attack_pattern(path, cross_account)
            primary_pattern = pattern_list[0]

            finding = {
                "principal": principal_name,
                "account_id": principal.account_id,
                "capability": cap_class,
                "risk": risk,
                "severity": severity,
                "cross_account": cross_account,
                "path": path,
                "pattern": primary_pattern["pattern"],
                "mitre": primary_pattern["mitre"],
                "all_patterns": pattern_list
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
        "dominators": dominators
    }

    return findings, criticality, remediation_summary


# ============================================================
# 📊 Extract Graph Data (with Cross-Account Visualization)
# ============================================================

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

                    if src in graph.nodes and dst in graph.nodes:
                        if src in graph.adjacency:
                            if src in graph.nodes and dst in graph.nodes:
                                if src in graph.nodes and dst in graph.nodes:
                                    pass

                    # Proper cross-account detection
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