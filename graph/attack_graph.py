from collections import defaultdict
from models.authorization_model import is_critical_action
from semantics.evaluator import IAMSemanticEvaluator
from semantics.evaluator import IAMSemanticEvaluator


class AttackGraph:

    def __init__(self):
        self.adjacency = defaultdict(set)
        self.nodes = set()

    def add_edge(self, src, dst):
        self.nodes.add(src)
        self.nodes.add(dst)
        self.adjacency[src].add(dst)

    def neighbors(self, node):
        return self.adjacency[node]


def build_attack_graph(principals: dict):
    """
    principals: dict[str, Principal]
    """
    graph = AttackGraph()
    evaluator = IAMSemanticEvaluator(principals)

    # -------------
    # Direct edges
    # -------------
    for principal_name, principal in principals.items():

        # Direct critical capability edges
        for action in principal.allow_actions:
            if is_critical_action(action):
                capability_node = f"CAPABILITY::{action}"
                graph.add_edge(principal_name, capability_node)

    # -------------
    # AssumeRole edges
    # -------------
    for principal_name in principals:
        for role_name in principals:
            if principal_name == role_name:
                continue

            if evaluator.can_assume(principal_name, role_name):
                graph.add_edge(principal_name, role_name)

    # -------------
    # Role → Capability edges
    # -------------
    SERVICE_EXECUTION_ACTIONS = {
        "ec2:RunInstances",
        "lambda:CreateFunction",
        "ecs:RunTask"
    }

    for principal_name, principal in principals.items():
        has_passrole = evaluator.is_allowed(principal_name, "iam:PassRole")

        has_service_exec = any(
            evaluator.is_allowed(principal_name, action)
            for action in SERVICE_EXECUTION_ACTIONS
        )

        if has_passrole and has_service_exec:
            for role_name, role in principals.items():
                if role.type == "role":
                    graph.add_edge(principal_name, role_name)

    return graph
