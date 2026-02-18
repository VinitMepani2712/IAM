from collections import deque


def find_minimal_escalation_path(graph, attacker):
    from collections import deque

    visited = set()
    best_depth = {}
    parent = {}

    queue = deque([(attacker, 0)])

    while queue:
        node, depth = queue.popleft()

        # Dominance pruning
        if node in best_depth and depth >= best_depth[node]:
            continue

        best_depth[node] = depth

        # Found capability
        if node.startswith("CAPABILITY::"):
            return reconstruct_path(parent, attacker, node)

        for neighbor in graph.neighbors(node):
            parent[neighbor] = node
            queue.append((neighbor, depth + 1))

    return None

def reconstruct_path(parent, start, end):
    path = [end]
    current = end

    while current != start:
        current = parent[current]
        path.append(current)

    path.reverse()
    return path

def find_all_escalation_paths(graph, attacker):
    from collections import deque

    paths = []
    queue = deque([(attacker, [attacker])])

    while queue:
        node, path = queue.popleft()

        if node.startswith("CAPABILITY::"):
            paths.append(path)
            continue

        for neighbor in graph.neighbors(node):
            if neighbor not in path:  # prevent cycles
                queue.append((neighbor, path + [neighbor]))

    return paths
