from collections import defaultdict


def edge_cost(edge):
    src, dst = edge

    # Removing admin privilege is expensive
    if dst.startswith("CAPABILITY::AdministratorAccess"):
        return 5

    # Removing trust edges is moderate cost
    if not dst.startswith("CAPABILITY::"):
        return 2

    return 3


def suggest_ranked_remediation(paths):

    edge_frequency = defaultdict(int)

    for path in paths:
        for i in range(len(path) - 1):
            edge = (path[i], path[i + 1])
            edge_frequency[edge] += 1

    if not edge_frequency:
        return None

    scored_edges = []

    for edge, freq in edge_frequency.items():
        cost = edge_cost(edge)
        score = freq / cost
        scored_edges.append((edge, score))

    scored_edges.sort(key=lambda x: x[1], reverse=True)

    return scored_edges
