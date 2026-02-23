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
# ============================================================
# 🔍 Deep Dive: Single Principal Analysis
# ============================================================

def analyze_principal(principals, attacker):

    graph = build_attack_graph(principals)

    path = find_minimal_escalation_path(graph, attacker)

    print("\n=== Minimal Escalation Path ===")
    print(" → ".join(path) if path else "No escalation found.")

    paths = find_all_escalation_paths(graph, attacker)

    if not paths:
        print("\nNo escalation paths found.")
        return

    centrality = compute_escalation_centrality(paths)
    centrality_score = centrality.get(attacker, 0)

    findings = []
    valid_paths = []

    principal = principals[attacker]

    original_caps = set()

    for stmt in principal.policy_statements:
        if stmt.effect == "Allow":
            for action in stmt.actions:
                cap = classify_action(action)
                if cap:
                    original_caps.add(cap)

    print("\n=== Escalation Findings ===")

    for path in paths:

        capability_node = path[-1]
        cap_class = capability_node.split("::")[1]

        if cap_class in original_caps:
            continue

        valid_paths.append(path)

        path_length = len(path)

        accounts = [
            principals[node].account_id
            for node in path
            if node in principals
        ]

        cross_account = len(set(accounts)) > 1

        risk = compute_risk(
            capability_class=cap_class,
            path_length=path_length,
            centrality_score=centrality_score,
            cross_account=cross_account
        )

        severity = classify_severity(risk)

        pattern_list = classify_attack_pattern(path, cross_account)

    

        primary_pattern = pattern_list[0]
        attack_pattern = primary_pattern["pattern"]
        mitre_tag = primary_pattern["mitre"]
        all_patterns = pattern_list

        finding = {
            "principal": attacker,
            "account_id": principal.account_id,
            "escalation_class": cap_class,
            "risk_score": risk,
            "severity": severity,
            "cross_account": cross_account,
            "path": path,
            "attack_pattern": attack_pattern,
            "mitre_tag": mitre_tag,
            "all_patterns": all_patterns
        }

        findings.append(finding)

        print(f"Escalation: {cap_class}")
        print(f"Risk Score: {risk}")
        print(f"Severity: {severity}")
        print(f"Cross-Account: {cross_account}")
        print(f"Pattern: {attack_pattern}")
        print(f"MITRE: {mitre_tag}")
        print(f"Path: {' → '.join(path)}")
        print("-" * 60)

    # Weighted Minimal Cut
    if valid_paths:

    # Dominator Analysis
        dominators = compute_dominators(valid_paths)

        if dominators:
            print("\n=== Dominator Analysis (Structural Choke Points) ===")
            for node in dominators:
                print(f"{node} (appears in every escalation path)")
        else:
            print("\nNo strict dominators found.")

        # Weighted Minimal Cut
        cut_edges = compute_weighted_minimal_cut(valid_paths)

        print("\n=== Weighted Minimal Cut Remediation ===")
        for edge in cut_edges:
            print(f"Remove edge {edge}")

    generate_risk_report(findings)
    visualize_attack_graph(graph, path)


# Full Environment Audit
# ============================================================

def analyze_environment(principals):

    graph = build_attack_graph(principals)

    print("\n=== Full Environment Escalation Audit ===\n")
    print("Principal | Escalation | Risk | Severity | Cross-Account | Pattern | MITRE")
    print("--------------------------------------------------------------------------------")

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

        centrality = compute_escalation_centrality(paths)
        centrality_score = centrality.get(principal_name, 0)

        valid_paths = []

        for path in paths:

            capability_node = path[-1]
            cap_class = capability_node.split("::")[1]

            if cap_class in original_caps:
                continue

            valid_paths.append(path)

            path_length = len(path)

            accounts = [
                principals[node].account_id
                for node in path
                if node in principals
            ]

            cross_account = len(set(accounts)) > 1

            risk = compute_risk(
                capability_class=cap_class,
                path_length=path_length,
                centrality_score=centrality_score,
                cross_account=cross_account
            )

            severity = classify_severity(risk)

            pattern_list = classify_attack_pattern(path, cross_account)
            primary_pattern = pattern_list[0]
            attack_pattern = primary_pattern["pattern"]
            mitre_tag = primary_pattern["mitre"]
            all_patterns = pattern_list

            finding = {
                "principal": principal_name,
                "account_id": principal.account_id,
                "escalation_class": cap_class,
                "risk_score": risk,
                "severity": severity,
                "cross_account": cross_account,
                "path": path,
                "attack_pattern": attack_pattern,
                "mitre_tag": mitre_tag,
                "all_patterns": all_patterns
            }

            findings.append(finding)

            print(
                f"{principal_name} | {cap_class} | {risk} | "
                f"{severity} | {cross_account} | "
                f"{attack_pattern} | {mitre_tag}"
            )

        # Weighted Minimal Cut per principal
        if valid_paths:

    # Dominator Analysis
            dominators = compute_dominators(valid_paths)

            if dominators:
                print(f"\nDominators for {principal_name}:")
                for node in dominators:
                    print(f"  {node} (structural choke point)")

            # Weighted Minimal Cut
            cut_edges = compute_weighted_minimal_cut(valid_paths)

            print(f"\nWeighted Minimal Cut for {principal_name}:")
            for edge in cut_edges:
                print(f"  Remove edge {edge}")
            print("-" * 60)

    if findings:

        criticality = compute_node_criticality(findings)
        print("\n=== Top 10 Most Critical Nodes ===")
        for node, score in list(criticality.items())[:10]:
            print(f"{node} → {round(score, 2)}")

        generate_risk_report(findings)
        generate_global_dashboard(principals, findings, criticality)

        print("\nRisk report and dashboard generated.")
    else:
        print("\nNo escalation findings.")


def main():

    parser = argparse.ArgumentParser(
        description="IAM Risk Engine - Graph-Based Cloud IAM Risk Analyzer"
    )

    parser.add_argument(
        "input",
        nargs="?",
        help="IAM JSON file path OR principal name (if file provided first)"
    )

    parser.add_argument(
        "principal",
        nargs="?",
        help="Optional principal for deep dive analysis"
    )

    parser.add_argument(
        "--live",
        action="store_true",
        help="Fetch IAM configuration live from AWS"
    )

    parser.add_argument(
        "--profile",
        help="AWS profile (used with --live)"
    )

    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Simulate enterprise-scale IAM environment"
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
            users_per_account=20
        )
        analyze_environment(principals)
        return

    # ---------------------------------------------------------
    # Live AWS Mode
    # ---------------------------------------------------------
    if args.live:
        print("\nFetching IAM configuration from AWS...\n")
        data = fetch_account_authorization(profile=args.profile)
        principals = parse_aws_iam_json(data)

        if args.input:
            analyze_principal(principals, args.input)
        else:
            analyze_environment(principals)
        return

    # ---------------------------------------------------------
    # File Mode (Default)
    # ---------------------------------------------------------
    if args.input:
        principals = parse_aws_iam_json(args.input)

        if args.principal:
            analyze_principal(principals, args.principal)
        else:
            analyze_environment(principals)
        return

    
if __name__ == "__main__":
    main()