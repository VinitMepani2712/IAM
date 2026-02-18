import sys
from models.entities import Principal
from graph.attack_graph import build_attack_graph
from graph.reachability import (
    find_minimal_escalation_path,
    find_all_escalation_paths
)
from analysis.centrality import compute_escalation_centrality
from analysis.remediation import suggest_ranked_remediation
from analysis.visualization import visualize_attack_graph
from parsers.aws_parser import parse_aws_iam_json
from benchmarks.scalability import run_scalability_test


def analyze_principals(principals, attacker):

    graph = build_attack_graph(principals)

    # Minimal path
    path = find_minimal_escalation_path(graph, attacker)

    print("\n=== Minimal Escalation Path ===")
    print(" → ".join(path) if path else "No escalation found.")

    # All paths
    paths = find_all_escalation_paths(graph, attacker)

    # Centrality
    centrality = compute_escalation_centrality(paths)

    print("\n=== Escalation Centrality ===")
    for node, score in centrality.items():
        print(f"{node}: {score}")

    # Ranked remediation
    ranked = suggest_ranked_remediation(paths)

    print("\n=== Ranked Remediation Suggestions ===")
    if ranked:
        for edge, score in ranked:
            print(f"Remove edge {edge} | Priority Score: {round(score,2)}")
    else:
        print("No remediation needed.")

    visualize_attack_graph(graph, path)


def demo_synthetic():
    user = Principal(
        name="UserA",
        type="user",
        allow_actions={"sts:AssumeRole"},
        deny_actions=set(),
        trusts=set()
    )

    role1 = Principal(
        name="Role1",
        type="role",
        allow_actions={"sts:AssumeRole"},
        deny_actions=set(),
        trusts={"UserA"}
    )

    role_admin = Principal(
        name="RoleAdmin",
        type="role",
        allow_actions={"AdministratorAccess"},
        deny_actions=set(),
        trusts={"Role1"}
    )

    principals = {
        "UserA": user,
        "Role1": role1,
        "RoleAdmin": role_admin
    }

    analyze_principals(principals, "UserA")


def analyze_aws_file(file_path, attacker=None):

    principals = parse_aws_iam_json(file_path)

    if not principals:
        print("No principals found.")
        return

    if attacker:
        analyze_principals(principals, attacker)
        return

    print("\n=== Full Environment Escalation Audit ===\n")

    escalation_summary = []

    for principal_name, principal in principals.items():

        # Skip principals that already directly have critical privilege
        already_critical = any(
            action == "AdministratorAccess"
            for action in principal.allow_actions
        )

        if already_critical:
            continue

        graph = build_attack_graph(principals)
        paths = find_all_escalation_paths(graph, principal_name)

        if paths:
            escalation_summary.append((principal_name, len(paths)))


    if not escalation_summary:
        print("No principals can escalate privileges.")
        return

    escalation_summary.sort(key=lambda x: x[1], reverse=True)

    print("Principal | Escalation Path Count")
    print("----------------------------------")

    for principal, count in escalation_summary:
        print(f"{principal} | {count}")

    print("\nRun with specific principal to visualize:")
    print("python main.py aws_sample.json <PrincipalName>")



if __name__ == "__main__":

    # No arguments → synthetic demo
    if len(sys.argv) == 1:
        print("Running synthetic demo...\n")
        demo_synthetic()

    # Benchmark mode
    elif sys.argv[1] == "--benchmark":
        from benchmarks.scalability import run_scalability_test
        run_scalability_test()

    # AWS file analysis mode
    else:
        file_path = sys.argv[1]
        attacker = sys.argv[2] if len(sys.argv) > 2 else None
        analyze_aws_file(file_path, attacker)
