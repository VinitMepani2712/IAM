from collections import defaultdict


def compute_escalation_centrality(paths):
    """
    paths: list of escalation paths
    """
    role_counts = defaultdict(int)
    total_paths = len(paths)

    if total_paths == 0:
        return {}

    for path in paths:
        for node in path:
            if node.startswith("CAPABILITY::"):
                continue
            role_counts[node] += 1

    centrality = {
        role: round(count / total_paths, 3)
        for role, count in role_counts.items()
    }

    return centrality
