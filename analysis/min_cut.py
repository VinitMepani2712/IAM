from collections import defaultdict
from analysis.edge_cost import edge_removal_cost


def compute_weighted_minimal_cut(paths):

    # Convert paths to edge sets
    edge_sets = []

    for path in paths:
        edges = set()
        for i in range(len(path) - 1):
            edges.add((path[i], path[i + 1]))
        edge_sets.append(edges)

    selected_edges = []

    while edge_sets:

        # Compute weighted coverage score
        edge_scores = defaultdict(float)

        for edges in edge_sets:
            for edge in edges:
                cost = edge_removal_cost(edge)
                edge_scores[edge] += 1 / cost   # More coverage, lower cost = better

        # Pick edge with highest weighted score
        best_edge = max(edge_scores, key=edge_scores.get)

        selected_edges.append(best_edge)

        # Remove all paths covered by this edge
        edge_sets = [edges for edges in edge_sets if best_edge not in edges]

    return selected_edges
