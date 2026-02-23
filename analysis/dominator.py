def compute_dominators(paths):
    """
    Given all escalation paths for a principal,
    compute nodes that appear in every path.
    """

    if not paths:
        return set()

    # Convert each path to set of nodes (excluding source)
    path_node_sets = [
        set(path[1:-1])  # exclude source and capability
        for path in paths
    ]

    # Intersection of all path node sets
    dominators = set.intersection(*path_node_sets)

    return dominators