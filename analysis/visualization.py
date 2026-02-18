import networkx as nx
import matplotlib.pyplot as plt


def visualize_attack_graph(graph, escalation_path=None):
    """
    graph: AttackGraph object
    escalation_path: list of nodes representing minimal escalation path
    """

    G = nx.DiGraph()

    # Add edges
    for src in graph.nodes:
        for dst in graph.neighbors(src):
            G.add_edge(src, dst)

    pos = nx.spring_layout(G, seed=42)

    node_colors = []
    edge_colors = []

    # Determine node colors
    for node in G.nodes():
        if escalation_path and node in escalation_path:
            node_colors.append("red")
        elif node.startswith("CAPABILITY::"):
            node_colors.append("orange")
        else:
            node_colors.append("lightblue")

    # Determine edge colors
    for edge in G.edges():
        if escalation_path and edge_in_path(edge, escalation_path):
            edge_colors.append("red")
        else:
            edge_colors.append("gray")

    plt.figure(figsize=(10, 7))

    nx.draw(
        G,
        pos,
        with_labels=True,
        node_color=node_colors,
        edge_color=edge_colors,
        node_size=2000,
        font_size=8,
        arrows=True
    )

    plt.title("IAM Attack Graph")
    plt.show()


def edge_in_path(edge, path):
    for i in range(len(path) - 1):
        if (path[i], path[i + 1]) == edge:
            return True
    return False
