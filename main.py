import argparse

from analysis.criticality import compute_node_criticality
from core.entities import Principal
from core.privilege_model import classify_action
from analysis.risk_model import compute_risk, classify_severity
from analysis.report import generate_risk_report
from analysis.min_cut import compute_weighted_minimal_cut
from analysis.attack_patterns import classify_attack_pattern

from graph.attack_graph import build_attack_graph
from graph.reachability import (
    find_minimal_escalation_path,
    find_all_escalation_paths
)
from analysis.dominator import compute_dominators
from analysis.centrality import compute_escalation_centrality
from analysis.visualization import visualize_attack_graph

from cloud.aws.parser import parse_aws_iam_json
from cloud.aws.live_fetch import fetch_account_authorization
from benchmarks.scalability import run_scalability_test
from simulation.enterprise_generator import generate_enterprise_environment
from analysis.dashboard import generate_global_dashboard


# =========
# Helpers
# =========

def _build_condition_flags(path, principals):
    """Walk every role in the path and collect trust conditions."""
    flags = {
        "requires_mfa":         False,
        "requires_external_id": False,
        "source_ip_restricted": False,
        "org_id_required":      False,
        "region_restricted":    False,
        "condition_summary":    [],
    }
    for node in path:
        p_obj = principals.get(node)
        if not p_obj:
            continue
        tc_map = getattr(p_obj, "trust_conditions", {}) or {}
        for tc in tc_map.values():
            if tc.requires_mfa:
                flags["requires_mfa"] = True
                flags["condition_summary"].append(f"{node}: MFA required")
            if tc.requires_external_id:
                flags["requires_external_id"] = True
                eid_str = f" ({tc.external_id_value})" if tc.external_id_value else ""
                flags["condition_summary"].append(f"{node}: ExternalId{eid_str} required")
            if tc.source_ip_restricted:
                flags["source_ip_restricted"] = True
                flags["condition_summary"].append(f"{node}: Source IP restricted")
            if tc.org_id_required:
                flags["org_id_required"] = True
                flags["condition_summary"].append(f"{node}: Org ID required")
            if tc.region_restricted:
                flags["region_restricted"] = True
                flags["condition_summary"].append(f"{node}: Region restricted")
    return flags


def _save_pdf(findings, principals):
    """Generate and save a PDF risk report to the current directory."""
    from pdf.pdf_report import generate_pdf_report
    criticality = compute_node_criticality(findings)
    all_paths = [f["path"] for f in findings]
    cut_edges  = compute_weighted_minimal_cut(all_paths) if all_paths else []
    doms       = compute_dominators(all_paths) if all_paths else []
    remediation = {
        "total_paths":       len(all_paths),
        "recommended_fixes": cut_edges,
        "dominators":        sorted(doms) if doms else [],
    }
    pdf_bytes = generate_pdf_report(findings, criticality, remediation, len(principals))
    out_path = "iam_risk_report.pdf"
    with open(out_path, "wb") as fh:
        fh.write(pdf_bytes)
    print(f"\nPDF report saved: {out_path}")


# =========
# Deep Dive: Single Principal Analysis
# =========

def analyze_principal(principals, attacker, scps=None, output_pdf=False):

    graph = build_attack_graph(principals, scps=scps)
    path  = find_minimal_escalation_path(graph, attacker)

    print("\n=== Minimal Escalation Path ===")
    print(" → ".join(path) if path else "No escalation found.")

    paths = find_all_escalation_paths(graph, attacker)

    if not paths:
        print("\nNo escalation paths found.")
        return

    centrality       = compute_escalation_centrality(paths)
    centrality_score = centrality.get(attacker, 0)

    findings    = []
    valid_paths = []

    principal     = principals[attacker]
    original_caps = set()

    for stmt in principal.policy_statements:
        if stmt.effect == "Allow":
            for action in stmt.actions:
                cap = classify_action(action)
                if cap:
                    original_caps.add(cap)

    print("\n=== Escalation Findings ===")

    for p in paths:
        capability_node = p[-1]
        if not capability_node.startswith("CAPABILITY::"):
            continue

        cap_class = capability_node.split("::")[1]

        if cap_class in original_caps:
            continue

        valid_paths.append(p)

        accounts      = [principals[n].account_id for n in p if n in principals]
        cross_account = len(set(accounts)) > 1

        condition_flags = _build_condition_flags(p, principals)

        risk     = compute_risk(
            capability_class=cap_class,
            path_length=len(p),
            centrality_score=centrality_score,
            cross_account=cross_account,
            requires_mfa=condition_flags["requires_mfa"],
            requires_external_id=condition_flags["requires_external_id"],
            source_ip_restricted=condition_flags["source_ip_restricted"],
            org_id_required=condition_flags["org_id_required"],
            region_restricted=condition_flags["region_restricted"],
        )
        severity = classify_severity(risk)

        pattern_list    = classify_attack_pattern(p, cross_account)
        primary_pattern = pattern_list[0]

        finding = {
            "principal":       attacker,
            "account_id":      principal.account_id,
            "capability":      cap_class,
            "risk":            risk,
            "severity":        severity,
            "cross_account":   cross_account,
            "path":            p,
            "pattern":         primary_pattern["pattern"],
            "mitre":           primary_pattern["mitre"],
            "all_patterns":    pattern_list,
            "condition_flags": condition_flags,
        }

        findings.append(finding)

        print(f"Escalation : {cap_class}")
        print(f"Risk Score : {risk}")
        print(f"Severity   : {severity}")
        print(f"Cross-Acct : {cross_account}")
        print(f"Pattern    : {primary_pattern['pattern']}")
        print(f"MITRE      : {primary_pattern['mitre']}")
        print(f"Path       : {' → '.join(p)}")
        if condition_flags["condition_summary"]:
            print(f"Conditions : {', '.join(condition_flags['condition_summary'])}")
        print("-" * 60)

    if valid_paths:
        dominators = compute_dominators(valid_paths)

        if dominators:
            print("\n=== Dominator Analysis (Structural Choke Points) ===")
            for node in dominators:
                print(f"  {node}  (appears in every escalation path)")
        else:
            print("\nNo strict dominators found.")

        cut_edges = compute_weighted_minimal_cut(valid_paths)

        print("\n=== Weighted Minimal Cut Remediation ===")
        for edge in cut_edges:
            print(f"  Remove edge {edge}")

    generate_risk_report(findings)
    visualize_attack_graph(graph, path)

    if output_pdf and findings:
        _save_pdf(findings, principals)


# =========
# Full Environment Audit
# =========

def analyze_environment(principals, scps=None, output_pdf=False):

    graph = build_attack_graph(principals, scps=scps)

    print("\n=== Full Environment Escalation Audit ===\n")
    print("Principal | Escalation | Risk | Severity | Cross-Account | Pattern | MITRE")
    print("-" * 80)

    findings = []

    for principal_name, principal in principals.items():

        paths = find_all_escalation_paths(graph, principal_name)

        if not paths:
            continue

        original_caps = set()

        for stmt in principal.policy_statements:
            if stmt.effect == "Allow":
                for action in stmt.actions:
                    cap = classify_action(action)
                    if cap:
                        original_caps.add(cap)

        centrality       = compute_escalation_centrality(paths)
        centrality_score = centrality.get(principal_name, 0)

        valid_paths = []

        for p in paths:
            capability_node = p[-1]
            if not capability_node.startswith("CAPABILITY::"):
                continue

            cap_class = capability_node.split("::")[1]

            if cap_class in original_caps:
                continue

            valid_paths.append(p)

            accounts      = [principals[n].account_id for n in p if n in principals]
            cross_account = len(set(accounts)) > 1

            condition_flags = _build_condition_flags(p, principals)

            risk     = compute_risk(
                capability_class=cap_class,
                path_length=len(p),
                centrality_score=centrality_score,
                cross_account=cross_account,
                requires_mfa=condition_flags["requires_mfa"],
                requires_external_id=condition_flags["requires_external_id"],
                source_ip_restricted=condition_flags["source_ip_restricted"],
                org_id_required=condition_flags["org_id_required"],
                region_restricted=condition_flags["region_restricted"],
            )
            severity = classify_severity(risk)

            pattern_list    = classify_attack_pattern(p, cross_account)
            primary_pattern = pattern_list[0]

            finding = {
                "principal":       principal_name,
                "account_id":      principal.account_id,
                "capability":      cap_class,
                "risk":            risk,
                "severity":        severity,
                "cross_account":   cross_account,
                "path":            p,
                "pattern":         primary_pattern["pattern"],
                "mitre":           primary_pattern["mitre"],
                "all_patterns":    pattern_list,
                "condition_flags": condition_flags,
            }

            findings.append(finding)

            print(
                f"{principal_name} | {cap_class} | {risk} | "
                f"{severity} | {cross_account} | "
                f"{primary_pattern['pattern']} | {primary_pattern['mitre']}"
            )

        if valid_paths:
            dominators = compute_dominators(valid_paths)

            if dominators:
                print(f"\nDominators for {principal_name}:")
                for node in dominators:
                    print(f"  {node}  (structural choke point)")

            cut_edges = compute_weighted_minimal_cut(valid_paths)

            print(f"\nWeighted Minimal Cut for {principal_name}:")
            for edge in cut_edges:
                print(f"  Remove edge {edge}")
            print("-" * 60)

    if findings:
        criticality = compute_node_criticality(findings)

        print("\n=== Top 10 Most Critical Nodes ===")
        for node, score in list(criticality.items())[:10]:
            print(f"  {node}  →  {round(score, 2)}")

        generate_risk_report(findings)
        generate_global_dashboard(principals, findings, criticality)
        print("\nRisk report and dashboard generated.")

        if output_pdf:
            _save_pdf(findings, principals)
    else:
        print("\nNo escalation findings.")


def main():

    parser = argparse.ArgumentParser(
        description="IAM Defender — Graph-Based Cloud IAM Privilege Escalation Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py aws_export.json                   # Full environment audit
  python main.py aws_export.json UserA             # Deep-dive on one principal
  python main.py aws_export.json --pdf             # Audit + PDF report
  python main.py --live                            # Fetch live from AWS
  python main.py --live --profile dev UserA        # Live fetch, single principal
  python main.py --simulate                        # Enterprise simulation demo
        """,
    )

    parser.add_argument(
        "input",
        nargs="?",
        help="IAM JSON file path",
    )
    parser.add_argument(
        "principal",
        nargs="?",
        help="Optional: specific principal name for deep-dive analysis",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Fetch IAM configuration live from AWS",
    )
    parser.add_argument(
        "--profile",
        help="AWS CLI profile name (used with --live)",
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Generate and analyse a synthetic enterprise IAM environment",
    )
    parser.add_argument(
        "--pdf",
        action="store_true",
        help="Export a PDF risk report (iam_risk_report.pdf) after analysis",
    )

    args = parser.parse_args()

    # ---------------------------------------------------------
    # Enterprise Simulation Mode
    # ---------------------------------------------------------
    if args.simulate:
        print("\nGenerating enterprise-scale IAM environment...\n")
        principals = generate_enterprise_environment(
            num_accounts=10,
            roles_per_account=200,
            users_per_account=20,
        )
        analyze_environment(principals, output_pdf=args.pdf)
        return

    # ---------------------------------------------------------
    # Live AWS Mode
    # ---------------------------------------------------------
    if args.live:
        print("\nFetching IAM configuration from AWS...\n")
        data                = fetch_account_authorization(profile=args.profile)
        principals, scps    = parse_aws_iam_json(data)

        if args.input:
            analyze_principal(principals, args.input, scps=scps, output_pdf=args.pdf)
        else:
            analyze_environment(principals, scps=scps, output_pdf=args.pdf)
        return

    # ---------------------------------------------------------
    # File Mode
    # ---------------------------------------------------------
    if args.input:
        principals, scps = parse_aws_iam_json(args.input)

        if args.principal:
            analyze_principal(principals, args.principal, scps=scps, output_pdf=args.pdf)
        else:
            analyze_environment(principals, scps=scps, output_pdf=args.pdf)
        return

    # ---------------------------------------------------------
    # No arguments — print help
    # ---------------------------------------------------------
    parser.print_help()


if __name__ == "__main__":
    main()
