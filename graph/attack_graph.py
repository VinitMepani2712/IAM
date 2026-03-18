from collections import defaultdict
import fnmatch as _fnmatch
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
        if to_node not in self.adjacency_list[from_node]:  # prevent duplicate edges
            self.adjacency_list[from_node].append(to_node)

    def neighbors(self, node):
        return self.adjacency_list.get(node, [])

    adjacency = property(lambda self: self.adjacency_list)


# ── ARN parsing ───────────────────────────────────────────────────────────────
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


def _has_action(actions: set, prefix: str) -> bool:
    """
    Return True if `prefix` (e.g. 'iam:PassRole') is granted by any action
    in `actions`.  Handles:
      * exact match         — 'iam:PassRole'
      * full wildcard       — '*'
      * service wildcard    — 'iam:*'
      * partial wildcard    — 'iam:Pass*'  (fnmatch)
      * case insensitivity  — 'IAM:passrole' == 'iam:PassRole'
    """
    prefix_l = prefix.lower()
    for action in actions:
        a = action.lower()
        if a == prefix_l or a == "*":
            return True
        # service wildcard: iam:* matches iam:PassRole
        if ":" in prefix_l and a == prefix_l.split(":")[0] + ":*":
            return True
        # partial wildcard: iam:Pass* matches iam:PassRole
        if "*" in a and ":" in a:
            svc, pat = a.split(":", 1)
            tgt_svc, tgt_act = (prefix_l.split(":", 1) if ":" in prefix_l
                                 else ("", prefix_l))
            if (svc == "*" or svc == tgt_svc) and _fnmatch.fnmatch(tgt_act, pat):
                return True
    return False


def _cap(name: str):
    return f"CAPABILITY::{name}"


def _anode(action: str, target: str = None):
    return f"ACTION::{action}::{target}" if target else f"ACTION::{action}"


def _resource_match(deny_resource: str, actual_resource: str) -> bool:
    """
    Check if a deny resource pattern covers the actual resource.
    Handles: exact match, "*", and ARN wildcard patterns (fnmatch).
    """
    if deny_resource == "*" or deny_resource == actual_resource:
        return True
    return _fnmatch.fnmatch(actual_resource.lower(), deny_resource.lower())


def build_attack_graph(principals: dict, scps: list = None, resource_policies: list = None):

    g = AttackGraph()

    # ── Collect trust relationships ───────────────────────────────────────────
    role_trust_allows = defaultdict(set)
    for name, p in principals.items():
        if getattr(p, "type", None) == "role":
            for t in getattr(p, "trusts", set()) or set():
                normalized = _normalize_principal_token(t)
                if normalized:
                    role_trust_allows[name].add(normalized)

    # ── Add all principal nodes ───────────────────────────────────────────────
    for name in principals.keys():
        g.add_node(name)

    # ── AssumeRole edge builder (respects trust policy) ───────────────────────
    def add_assume_edge(caller: str, target_role: str):
        allowed = role_trust_allows.get(target_role, set())
        if allowed and caller not in allowed:
            return
        action_node = _anode("sts:AssumeRole", target_role)
        g.add_edge(caller, action_node)
        g.add_edge(action_node, target_role)

    # ── Build SCP global deny set ─────────────────────────────────────────────
    # SCPs act as a ceiling — if an action is denied here, no principal can
    # perform it regardless of their IAM permissions.
    scp_denies: set = set()
    for scp in (scps or []):
        for stmt in getattr(scp, "statements", []) or []:
            if getattr(stmt, "effect", "") == "Deny":
                for action in _actions(stmt):
                    for resource in _resources(stmt):
                        scp_denies.add((action.lower(), resource))

    # ── Parse policy statements ───────────────────────────────────────────────
    # Pre-build per-principal deny sets for fast lookup
    principal_denies = defaultdict(set)
    for name, p in principals.items():
        for stmt in getattr(p, "policy_statements", []) or []:
            if getattr(stmt, "effect", "") == "Deny":
                for action in _actions(stmt):
                    for resource in _resources(stmt):
                        principal_denies[name].add((action.lower(), resource))

    # ── Build per-principal boundary allowed-action sets ──────────────────────
    # A principal with a boundary can only perform actions that are BOTH
    # allowed by their identity policy AND allowed by the boundary.
    # If no boundary is set, all identity-policy allows are effective.
    principal_boundary_allows: dict = {}
    for name, p in principals.items():
        boundary = getattr(p, "permission_boundary", []) or []
        if boundary:
            allowed = set()
            for stmt in boundary:
                if getattr(stmt, "effect", "") == "Allow":
                    for action in _actions(stmt):
                        allowed.add(action.lower())
            principal_boundary_allows[name] = allowed

    def _boundary_permits(caller: str, action: str) -> bool:
        """Return True if the caller's boundary (if any) permits this action."""
        boundary_allows = principal_boundary_allows.get(caller)
        if boundary_allows is None:
            return True  # no boundary — identity policy is the only limit
        return _has_action(boundary_allows, action)

    def _is_denied(caller: str, action: str, resource: str) -> bool:
        """
        Return True if an explicit Deny (principal-level or SCP) covers
        this action+resource, OR if a permission boundary blocks the action.
        Uses the same wildcard logic as _has_action so patterns like
        iam:Pass*, arn:aws:iam::*:role/* are handled correctly.
        """
        # Permission boundary check (acts like an implicit deny if not allowed)
        if not _boundary_permits(caller, action):
            return True
        # Check SCP-level denies first (org-wide, highest priority)
        for (deny_action, deny_resource) in scp_denies:
            if _has_action({deny_action}, action) and _resource_match(deny_resource, resource):
                return True
        # Check principal-level explicit denies
        for (deny_action, deny_resource) in principal_denies.get(caller, set()):
            if _has_action({deny_action}, action) and _resource_match(deny_resource, resource):
                return True
        return False

    for name, p in principals.items():
        for stmt in getattr(p, "policy_statements", []) or []:
            if getattr(stmt, "effect", "Deny") != "Allow":
                continue

            actions   = _actions(stmt)
            resources = _resources(stmt)

            # ── sts:AssumeRole ────────────────────────────────────────────────
            if _has_action(actions, "sts:AssumeRole") or \
               _has_action(actions, "sts:AssumeRoleWithWebIdentity"):
                for r in resources:
                    if r == "*":
                        for role_name in role_trust_allows.keys():
                            role_arn = getattr(principals.get(role_name), "arn", role_name) or role_name
                            if not _is_denied(name, "sts:AssumeRole", role_arn):
                                add_assume_edge(name, role_name)
                    else:
                        rn = _role_name_from_arn(r) or r
                        if rn in principals and getattr(principals[rn], "type", None) == "role":
                            if not _is_denied(name, "sts:AssumeRole", r):
                                add_assume_edge(name, rn)

            # ── PassRole + EC2 ────────────────────────────────────────────────
            if (_has_action(actions, "iam:PassRole") and _has_action(actions, "ec2:RunInstances")
                    and not _is_denied(name, "iam:PassRole", "*")
                    and not _is_denied(name, "ec2:RunInstances", "*")):
                a = _anode("iam:PassRole+ec2:RunInstances")
                g.add_edge(name, a)
                g.add_edge(a, _cap("COMPUTE_LAUNCH"))

            # ── PassRole + Lambda ─────────────────────────────────────────────
            if (_has_action(actions, "iam:PassRole") and _has_action(actions, "lambda:CreateFunction")
                    and not _is_denied(name, "iam:PassRole", "*")
                    and not _is_denied(name, "lambda:CreateFunction", "*")):
                a = _anode("iam:PassRole+lambda:CreateFunction")
                g.add_edge(name, a)
                g.add_edge(a, _cap("COMPUTE_LAUNCH"))

            # ── Policy modification (role) ────────────────────────────────────
            for pol_action in ["iam:AttachRolePolicy", "iam:PutRolePolicy"]:
                if _has_action(actions, pol_action) and not _is_denied(name, pol_action, "*"):
                    a = _anode(pol_action)
                    g.add_edge(name, a)
                    g.add_edge(a, _cap("POLICY_MODIFICATION"))

            # ── Policy modification (user) ────────────────────────────────────
            for pol_action in ["iam:AttachUserPolicy", "iam:PutUserPolicy"]:
                if _has_action(actions, pol_action) and not _is_denied(name, pol_action, "*"):
                    a = _anode(pol_action)
                    g.add_edge(name, a)
                    g.add_edge(a, _cap("POLICY_MODIFICATION"))

            # ── Access key persistence ────────────────────────────────────────
            if _has_action(actions, "iam:CreateAccessKey") and not _is_denied(name, "iam:CreateAccessKey", "*"):
                a = _anode("iam:CreateAccessKey")
                g.add_edge(name, a)
                g.add_edge(a, _cap("ACCESS_KEY_PERSISTENCE"))

            # ── Console access takeover ───────────────────────────────────────
            # CreateLoginProfile: create a console password for another user
            # UpdateLoginProfile: reset another user's console password
            for login_action in ["iam:CreateLoginProfile", "iam:UpdateLoginProfile"]:
                if _has_action(actions, login_action) and not _is_denied(name, login_action, "*"):
                    a = _anode(login_action)
                    g.add_edge(name, a)
                    g.add_edge(a, _cap("CONSOLE_ACCESS"))

            # ── Identity creation ─────────────────────────────────────────────
            if _has_action(actions, "iam:CreateUser") and not _is_denied(name, "iam:CreateUser", "*"):
                a = _anode("iam:CreateUser")
                g.add_edge(name, a)
                g.add_edge(a, _cap("IDENTITY_CREATION"))

            # ── Wildcard IAM privilege ────────────────────────────────────────
            # Only add if iam:* or * is not itself denied
            if ("iam:*" in actions or "*" in actions) and \
               not _is_denied(name, "iam:*", "*") and not _is_denied(name, "*", "*"):
                g.add_edge(name, _cap("PRIVILEGE_PROPAGATION"))
                g.add_edge(name, _cap("CONSOLE_ACCESS"))
                g.add_edge(name, _cap("ACCESS_KEY_PERSISTENCE"))

            # ── Low-impact read / recon capabilities ──────────────────────────
            for read_action, cap_name in [
                ("s3:GetObject",                "DATA_READ"),
                ("s3:ListBucket",               "DATA_READ"),
                ("logs:GetLogEvents",           "LOG_ACCESS"),
                ("logs:DescribeLogGroups",       "LOG_ACCESS"),
                ("cloudtrail:LookupEvents",      "AUDIT_READ"),
                ("iam:ListRoles",               "RECON"),
                ("iam:GetRole",                 "RECON"),
                ("iam:SimulatePrincipalPolicy",  "RECON"),
            ]:
                if _has_action(actions, read_action) and not _is_denied(name, read_action, "*"):
                    a = _anode(read_action)
                    g.add_edge(name, a)
                    g.add_edge(a, _cap(cap_name))

    # ── Resource-based policy edges ───────────────────────────────────────────
    # For Lambda resources: if principal P can invoke function F (via resource
    # policy), and F has execution role R that is a known principal, add a
    # virtual trust edge P → R so the escalation engine can traverse it.
    for rp in (resource_policies or []):
        exec_role_name = _role_name_from_arn(rp.execution_role or "") if rp.execution_role else None
        if rp.resource_type == "lambda" and exec_role_name and exec_role_name in principals:
            invoke_actions = {"lambda:invokefunction", "lambda:*", "*"}
            if rp.allowed_actions & invoke_actions:
                for p_arn in rp.allowed_principals:
                    caller = _role_name_from_arn(p_arn) or p_arn.split("/")[-1]
                    if caller in principals:
                        # Add a virtual assume-role edge through a labelled action node
                        a = _anode(f"lambda:InvokeFunction({exec_role_name})")
                        g.add_edge(caller, a)
                        g.add_edge(a, exec_role_name)

    # ── Attached managed policy detection ─────────────────────────────────────
    for name, p in principals.items():
        if getattr(p, "type", None) != "role":
            continue

        policies = []
        for attr in ("attached_managed_policies", "raw_attached_managed_policies",
                     "AttachedManagedPolicies"):
            val = getattr(p, attr, None)
            if val:
                policies.extend(val)

        if any(pol.get("PolicyName") == "AdministratorAccess" for pol in policies):
            g.add_edge(name, _cap("FULL_ADMIN"))
            g.add_edge(name, _cap("PRIVILEGE_PROPAGATION"))

    return g