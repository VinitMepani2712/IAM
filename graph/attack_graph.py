from collections import defaultdict
import re


class AttackGraph:

    def __init__(self):
        self.nodes = set()
        self.adjacency_list = {}

    def add_node(self, node):
        self.nodes.add(node)
        if node not in self.adjacency_list:
            self.adjacency_list[node] = []

    def add_edge(self, from_node, to_node):
        self.add_node(from_node)
        self.add_node(to_node)
        self.adjacency_list[from_node].append(to_node)

    def neighbors(self, node):
        return self.adjacency_list.get(node, [])

    adjacency = property(lambda self: self.adjacency_list)


# ARN parsing
ARN_ROLE_RE = re.compile(r":role\/([^\/]+)$")
ARN_USER_RE = re.compile(r":user\/([^\/]+)$")


def _role_name_from_arn(arn: str):
    if not arn:
        return None
    m = ARN_ROLE_RE.search(arn)
    return m.group(1) if m else None


def _user_name_from_arn(arn: str):
    if not arn:
        return None
    m = ARN_USER_RE.search(arn)
    return m.group(1) if m else None


def _normalize_principal_token(token: str):
    if not token:
        return None
    if token.startswith("arn:aws:iam::"):
        rn = _role_name_from_arn(token)
        if rn:
            return rn
        un = _user_name_from_arn(token)
        if un:
            return un
    return token


def _actions(stmt):
    a = getattr(stmt, "actions", None)
    return set(a) if a else set()


def _resources(stmt):
    r = getattr(stmt, "resources", None)
    return set(r) if r else {"*"}


def _has_action(actions: set, prefix: str):
    if prefix in actions:
        return True
    service = prefix.split(":")[0] + ":*"
    return service in actions or "*" in actions


def _capability_node(name: str):
    return f"CAPABILITY::{name}"


def _action_node(action: str, target: str = None):
    return f"ACTION::{action}::{target}" if target else f"ACTION::{action}"


def build_attack_graph(principals: dict):

    g = AttackGraph()
    for name, p in principals.items():
        if getattr(p, "type", None) == "role":
            print("\nROLE:", name)
            print("DIR:", dir(p))
            print("DICT:", p.__dict__)
            
    # Collect trust relationships
    role_trust_allows = defaultdict(set)
    for name, p in principals.items():
        if getattr(p, "type", None) == "role":
            for t in getattr(p, "trusts", set()) or set():
                role_trust_allows[name].add(_normalize_principal_token(t))

    # Add principal nodes
    for name in principals.keys():
        g.add_node(name)

    # AssumeRole edge builder
    def add_assume_edge(caller: str, target_role: str):
        allowed = role_trust_allows.get(target_role, set())
        if allowed and caller not in allowed:
            return
        action_node = _action_node("sts:AssumeRole", target_role)
        g.add_edge(caller, action_node)
        g.add_edge(action_node, target_role)

    # Parse policy statements
    for name, p in principals.items():
        for stmt in getattr(p, "policy_statements", []) or []:
            if getattr(stmt, "effect", "Deny") != "Allow":
                continue

            actions = _actions(stmt)
            resources = _resources(stmt)

            # sts:AssumeRole
            if _has_action(actions, "sts:AssumeRole"):
                for r in resources:
                    if r == "*":
                        for role_name in role_trust_allows.keys():
                            add_assume_edge(name, role_name)
                    else:
                        rn = _role_name_from_arn(r) or r
                        if rn in principals and getattr(principals[rn], "type", None) == "role":
                            add_assume_edge(name, rn)

            # PassRole + EC2
            if _has_action(actions, "iam:PassRole") and _has_action(actions, "ec2:RunInstances"):
                a = _action_node("iam:PassRole+ec2:RunInstances")
                g.add_edge(name, a)
                g.add_edge(a, _capability_node("COMPUTE_LAUNCH"))

            # PassRole + Lambda
            if _has_action(actions, "iam:PassRole") and _has_action(actions, "lambda:CreateFunction"):
                a = _action_node("iam:PassRole+lambda:CreateFunction")
                g.add_edge(name, a)
                g.add_edge(a, _capability_node("COMPUTE_LAUNCH"))

            # Wildcard IAM privilege
            if "iam:*" in actions or "*" in actions:
                g.add_edge(name, _capability_node("PRIVILEGE_PROPAGATION"))

    # Attached managed policy detection
    for name, p in principals.items():
        if getattr(p, "type", None) != "role":
            continue

        policies = []

        # parsed model format
        if hasattr(p, "attached_managed_policies") and p.attached_managed_policies:
            policies.extend(p.attached_managed_policies)

        if hasattr(p, "raw_attached_managed_policies") and p.raw_attached_managed_policies:
            policies.extend(p.raw_attached_managed_policies)

        # direct AWS JSON format
        if hasattr(p, "AttachedManagedPolicies") and p.AttachedManagedPolicies:
            policies.extend(p.AttachedManagedPolicies)

        if any(pol.get("PolicyName") == "AdministratorAccess" for pol in policies):
            g.add_edge(name, _capability_node("FULL_ADMIN"))
            g.add_edge(name, _capability_node("PRIVILEGE_PROPAGATION"))

    return g