def edge_removal_cost(edge):
    """
    Assign operational cost to removing an edge.
    Lower cost = easier/safer to remove.
    """

    src, dst = edge

    # Removing admin capability is very disruptive
    if "CAPABILITY::FULL_ADMIN" in dst:
        return 10

    # Removing policy modification capability is high cost
    if "CAPABILITY::POLICY_MODIFICATION" in dst:
        return 8

    # Removing trust edge between principals
    if not dst.startswith("CAPABILITY::"):
        return 2

    # Default
    return 5
