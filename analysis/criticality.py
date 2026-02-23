from collections import defaultdict

def compute_node_criticality(findings):

    node_path_count = defaultdict(int)
    node_risk_sum = defaultdict(float)
    node_cross_account_bonus = defaultdict(float)

    for finding in findings:

        path = finding.get("path", [])
        risk = finding.get("risk_score", finding.get("risk", 0))
        cross_account = finding.get("cross_account", False)

        for node in path:
            node_path_count[node] += 1
            node_risk_sum[node] += risk

            if cross_account:
                node_cross_account_bonus[node] += 1

    criticality_scores = {}

    for node in node_path_count:
        avg_risk = node_risk_sum[node] / node_path_count[node]
        bonus = 1 + (node_cross_account_bonus[node] * 0.1)

        criticality_scores[node] = (
            node_path_count[node] * avg_risk * bonus
        )

    return dict(sorted(
        criticality_scores.items(),
        key=lambda x: x[1],
        reverse=True
    ))