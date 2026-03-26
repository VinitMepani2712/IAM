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
            self.adjacency_list[node] = set()

    def add_edge(self, from_node, to_node):
        self.add_node(from_node)
        self.add_node(to_node)
        self.adjacency_list[from_node].add(to_node)

    def neighbors(self, node):
        return list(self.adjacency_list.get(node, set()))

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


def _capability_node(name: str):
    return f"CAPABILITY::{name}"


def _action_node(action: str, target: str = None):
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
        action_node = _action_node("sts:AssumeRole", target_role)
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
            if getattr(stmt, "effect", None) != "Allow":
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

            # Helper: is PassRole allowed on any role resource (not just a
            # tightly-scoped single ARN)?  Prevents false-positives when a
            # policy says Allow iam:PassRole Resource: arn:*:role/safe-only.
            passrole_broad = _has_action(actions, "iam:PassRole") and (
                "*" in resources
                or any(
                    r in ("arn:aws:iam::*:*", "arn:aws:iam::*:role/*")
                    or (":role/" in r and "*" in r)
                    for r in resources
                )
            )

            # ── PassRole + EC2 ────────────────────────────────────────────────
            if (passrole_broad and _has_action(actions, "ec2:RunInstances")
                    and not _is_denied(name, "iam:PassRole", "*")
                    and not _is_denied(name, "ec2:RunInstances", "*")):
                a = _action_node("iam:PassRole+ec2:RunInstances")
                g.add_edge(name, a)
                g.add_edge(a, _capability_node("COMPUTE_LAUNCH"))

            # ── PassRole + Lambda (create) ────────────────────────────────────
            if (passrole_broad and _has_action(actions, "lambda:CreateFunction")
                    and not _is_denied(name, "iam:PassRole", "*")
                    and not _is_denied(name, "lambda:CreateFunction", "*")):
                a = _action_node("iam:PassRole+lambda:CreateFunction")
                g.add_edge(name, a)
                g.add_edge(a, _capability_node("COMPUTE_LAUNCH"))

            # ── Lambda UpdateFunctionCode ─────────────────────────────────────
            # Can overwrite existing Lambda code without needing PassRole —
            # if the Lambda's execution role is powerful, this is escalation.
            if (_has_action(actions, "lambda:UpdateFunctionCode")
                    and not _is_denied(name, "lambda:UpdateFunctionCode", "*")):
                a = _action_node("lambda:UpdateFunctionCode")
                g.add_edge(name, a)
                g.add_edge(a, _capability_node("COMPUTE_LAUNCH"))

            # ── PassRole + Glue ───────────────────────────────────────────────
            if (passrole_broad and _has_action(actions, "glue:CreateJob")
                    and not _is_denied(name, "iam:PassRole", "*")
                    and not _is_denied(name, "glue:CreateJob", "*")):
                a = _action_node("iam:PassRole+glue:CreateJob")
                g.add_edge(name, a)
                g.add_edge(a, _capability_node("COMPUTE_LAUNCH"))

            # ── PassRole + CloudFormation ─────────────────────────────────────
            if (passrole_broad and _has_action(actions, "cloudformation:CreateStack")
                    and not _is_denied(name, "iam:PassRole", "*")
                    and not _is_denied(name, "cloudformation:CreateStack", "*")):
                a = _action_node("iam:PassRole+cloudformation:CreateStack")
                g.add_edge(name, a)
                g.add_edge(a, _capability_node("COMPUTE_LAUNCH"))

            # ── PassRole + ECS ────────────────────────────────────────────────
            if (passrole_broad and _has_action(actions, "ecs:RunTask")
                    and not _is_denied(name, "iam:PassRole", "*")
                    and not _is_denied(name, "ecs:RunTask", "*")):
                a = _action_node("iam:PassRole+ecs:RunTask")
                g.add_edge(name, a)
                g.add_edge(a, _capability_node("COMPUTE_LAUNCH"))

            # ── PassRole + SageMaker ──────────────────────────────────────────
            if (passrole_broad and _has_action(actions, "sagemaker:CreateTrainingJob")
                    and not _is_denied(name, "iam:PassRole", "*")
                    and not _is_denied(name, "sagemaker:CreateTrainingJob", "*")):
                a = _action_node("iam:PassRole+sagemaker:CreateTrainingJob")
                g.add_edge(name, a)
                g.add_edge(a, _capability_node("COMPUTE_LAUNCH"))

            # ── Policy modification (role) ────────────────────────────────────
            for pol_action in ["iam:AttachRolePolicy", "iam:PutRolePolicy",
                                "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"]:
                if _has_action(actions, pol_action) and not _is_denied(name, pol_action, "*"):
                    a = _action_node(pol_action)
                    g.add_edge(name, a)
                    g.add_edge(a, _capability_node("POLICY_MODIFICATION"))

            # ── Policy modification (user) ────────────────────────────────────
            for pol_action in ["iam:AttachUserPolicy", "iam:PutUserPolicy"]:
                if _has_action(actions, pol_action) and not _is_denied(name, pol_action, "*"):
                    a = _action_node(pol_action)
                    g.add_edge(name, a)
                    g.add_edge(a, _capability_node("POLICY_MODIFICATION"))

            # ── Access key persistence ────────────────────────────────────────
            if _has_action(actions, "iam:CreateAccessKey") and not _is_denied(name, "iam:CreateAccessKey", "*"):
                a = _action_node("iam:CreateAccessKey")
                g.add_edge(name, a)
                g.add_edge(a, _capability_node("ACCESS_KEY_PERSISTENCE"))

            # ── Console access takeover ───────────────────────────────────────
            for login_action in ["iam:CreateLoginProfile", "iam:UpdateLoginProfile"]:
                if _has_action(actions, login_action) and not _is_denied(name, login_action, "*"):
                    a = _action_node(login_action)
                    g.add_edge(name, a)
                    g.add_edge(a, _capability_node("CONSOLE_ACCESS"))

            # ── Identity creation ─────────────────────────────────────────────
            for id_action in ["iam:CreateUser", "iam:CreateRole"]:
                if _has_action(actions, id_action) and not _is_denied(name, id_action, "*"):
                    a = _action_node(id_action)
                    g.add_edge(name, a)
                    g.add_edge(a, _capability_node("IDENTITY_CREATION"))

            # ── Privilege propagation via group / trust manipulation ──────────
            for priv_action in [
                "iam:AddUserToGroup",           # add self/others to privileged group
                "iam:UpdateAssumeRolePolicy",   # modify role trust policy to trust self
                "iam:DeleteRolePermissionsBoundary",   # remove boundary → full permissions
                "iam:DeleteUserPermissionsBoundary",
            ]:
                if _has_action(actions, priv_action) and not _is_denied(name, priv_action, "*"):
                    a = _action_node(priv_action)
                    g.add_edge(name, a)
                    g.add_edge(a, _capability_node("PRIVILEGE_PROPAGATION"))

            # ── Wildcard IAM / full admin ─────────────────────────────────────
            is_full_wildcard = "*" in actions and not _is_denied(name, "*", "*")
            is_iam_wildcard  = _has_action(actions, "iam:*") and not _is_denied(name, "iam:*", "*")

            if is_full_wildcard:
                # Allow * on * = AdministratorAccess equivalent
                g.add_edge(name, _capability_node("FULL_ADMIN"))
                g.add_edge(name, _capability_node("PRIVILEGE_PROPAGATION"))
                g.add_edge(name, _capability_node("CONSOLE_ACCESS"))
                g.add_edge(name, _capability_node("ACCESS_KEY_PERSISTENCE"))

            elif is_iam_wildcard:
                g.add_edge(name, _capability_node("PRIVILEGE_PROPAGATION"))
                g.add_edge(name, _capability_node("CONSOLE_ACCESS"))
                g.add_edge(name, _capability_node("ACCESS_KEY_PERSISTENCE"))

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
                    a = _action_node(read_action)
                    g.add_edge(name, a)
                    g.add_edge(a, _capability_node(cap_name))

    # ── Resource-based policy edges ───────────────────────────────────────────
    for rp in (resource_policies or []):
        exec_role_name = _role_name_from_arn(rp.execution_role or "") if rp.execution_role else None
        allowed_lower  = {a.lower() for a in rp.allowed_actions}

        # ── Lambda: invoke → execution role ───────────────────────────────────
        # If principal P can invoke function F and F runs as role R, P can
        # exfiltrate R's credentials or inject malicious code via UpdateFunctionCode.
        if rp.resource_type == "lambda" and exec_role_name and exec_role_name in principals:
            invoke_actions = {"lambda:invokefunction", "lambda:*", "*"}
            if allowed_lower & invoke_actions:
                for p_arn in rp.allowed_principals:
                    caller = _role_name_from_arn(p_arn) or p_arn.split("/")[-1]
                    if caller in principals:
                        a = _action_node(f"lambda:InvokeFunction({exec_role_name})")
                        g.add_edge(caller, a)
                        g.add_edge(a, exec_role_name)

        # ── S3: cross-account read → DATA_READ capability ─────────────────────
        # A principal granted s3:GetObject or s3:ListBucket via a bucket policy
        # can exfiltrate data. Model as a direct DATA_READ capability edge.
        elif rp.resource_type == "s3":
            read_actions = {"s3:getobject", "s3:listbucket", "s3:*", "*"}
            if allowed_lower & read_actions:
                for p_arn in rp.allowed_principals:
                    caller = _role_name_from_arn(p_arn) or p_arn.split("/")[-1]
                    if caller in principals:
                        a = _action_node(f"s3:GetObject({rp.resource_arn})")
                        g.add_edge(caller, a)
                        g.add_edge(a, _capability_node("DATA_READ"))

        # ── SQS: send/receive → DATA_READ or PRIVILEGE_PROPAGATION ────────────
        # A principal that can send messages to a privileged queue (consumed by
        # a Lambda or EC2 worker running as a powerful role) gains indirect code
        # execution. Model as PRIVILEGE_PROPAGATION if exec_role is known,
        # otherwise DATA_READ.
        elif rp.resource_type == "sqs":
            write_actions = {"sqs:sendmessage", "sqs:*", "*"}
            if allowed_lower & write_actions:
                for p_arn in rp.allowed_principals:
                    caller = _role_name_from_arn(p_arn) or p_arn.split("/")[-1]
                    if caller in principals:
                        if exec_role_name and exec_role_name in principals:
                            a = _action_node(f"sqs:SendMessage({exec_role_name})")
                            g.add_edge(caller, a)
                            g.add_edge(a, exec_role_name)
                        else:
                            a = _action_node(f"sqs:SendMessage({rp.resource_arn})")
                            g.add_edge(caller, a)
                            g.add_edge(a, _capability_node("PRIVILEGE_PROPAGATION"))

    return g