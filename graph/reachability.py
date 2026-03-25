from collections import deque


def find_minimal_escalation_path(graph, attacker):
    """BFS — returns the shortest escalation path. O(V+E)."""
    best_depth = {}
    parent     = {}

    queue = deque([(attacker, 0)])

    while queue:
        node, depth = queue.popleft()

        if node in best_depth and depth >= best_depth[node]:
            continue
        best_depth[node] = depth

        if node.startswith("CAPABILITY::"):
            return _reconstruct(parent, attacker, node)

        for neighbor in graph.neighbors(node):
            parent[neighbor] = node
            queue.append((neighbor, depth + 1))

    return None


def _reconstruct(parent, start, end):
    path, current = [end], end
    while current != start:
        current = parent[current]
        path.append(current)
    path.reverse()
    return path


def find_all_escalation_paths(graph, attacker, max_depth=10):
    """
    DFS with backtracking — enumerates every simple escalation path.

    Uses a single mutable path stack (O(depth) memory) rather than
    copying the full path per queued state (O(P·L) memory in BFS).
    Cycle prevention is O(1) via a per-path visited set.
    max_depth caps exploration to avoid exponential blowup in dense graphs.
    """
    paths   = []
    visited = {attacker}
    stack   = [attacker]

    def dfs(node):
        if node.startswith("CAPABILITY::"):
            paths.append(list(stack))
            return
        if len(stack) >= max_depth:
            return
        for neighbor in graph.neighbors(node):
            if neighbor not in visited:
                visited.add(neighbor)
                stack.append(neighbor)
                dfs(neighbor)
                stack.pop()
                visited.discard(neighbor)

    dfs(attacker)
    return paths
