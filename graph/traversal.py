"""
graph/traversal.py
General-purpose directed graph traversal utilities.

Complements reachability.py (which is CAPABILITY-specific BFS) with
generic traversal primitives that can be reused by analysis modules.
"""

from collections import deque


def bfs_all_paths(graph, start, target_predicate, max_depth=None):
    """
    BFS over the attack graph from `start`, collecting every path whose
    final node satisfies `target_predicate`.  Cycles are prevented.

    Args:
        graph:            Attack graph object with a .neighbors() method.
        start:            Source node name.
        target_predicate: Callable(node) -> bool — True when the node is a goal.
        max_depth:        Optional int — prune paths longer than this.

    Returns:
        List of paths (each path is a list of node names).
    """
    paths = []
    queue = deque([(start, [start])])

    while queue:
        node, path = queue.popleft()

        if max_depth is not None and len(path) > max_depth:
            continue

        if target_predicate(node) and node != start:
            paths.append(path)
            continue

        for neighbor in graph.neighbors(node):
            if neighbor not in path:
                queue.append((neighbor, path + [neighbor]))

    return paths


def dfs_all_paths(graph, start, target_predicate, max_depth=None):
    """
    DFS variant — explores deeper paths first.  Useful when longer
    escalation chains are more interesting than short direct ones.

    Args:
        graph:            Attack graph object with a .neighbors() method.
        start:            Source node name.
        target_predicate: Callable(node) -> bool — True when the node is a goal.
        max_depth:        Optional int — prune paths longer than this.

    Returns:
        List of paths (each path is a list of node names).
    """
    paths = []

    def _dfs(node, path):
        if max_depth is not None and len(path) > max_depth:
            return
        if target_predicate(node) and node != start:
            paths.append(list(path))
            return
        for neighbor in graph.neighbors(node):
            if neighbor not in path:
                path.append(neighbor)
                _dfs(neighbor, path)
                path.pop()

    _dfs(start, [start])
    return paths


def ancestors(graph, node):
    """
    Return all nodes that can reach `node` via forward edges (reverse BFS).

    Useful for finding "who can escalate to this capability?".
    """
    result = set()
    queue = deque([node])

    while queue:
        current = queue.popleft()
        for candidate, neighbors in graph.adjacency.items():
            if current in neighbors and candidate not in result:
                result.add(candidate)
                queue.append(candidate)

    return result


def descendants(graph, node):
    """
    Return all nodes reachable FROM `node` via forward edges.

    Useful for finding "what can this principal reach?".
    """
    result = set()
    queue = deque([node])

    while queue:
        current = queue.popleft()
        for neighbor in graph.neighbors(current):
            if neighbor not in result:
                result.add(neighbor)
                queue.append(neighbor)

    return result


def shortest_path(graph, start, end):
    """
    Return the shortest path from `start` to `end` using BFS, or None
    if no path exists.
    """
    if start == end:
        return [start]

    visited = {start}
    queue = deque([(start, [start])])

    while queue:
        node, path = queue.popleft()
        for neighbor in graph.neighbors(node):
            if neighbor == end:
                return path + [neighbor]
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [neighbor]))

    return None
