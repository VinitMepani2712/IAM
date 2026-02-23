import fnmatch

class IAMSemanticEvaluator:

    def __init__(self, principals: dict):
        """
        principals: dict[str, Principal]
        """
        self.principals = principals

    # -------------------------
    # Action matching
    # -------------------------
    def _action_matches(self, action_set, required_action):
        for action in action_set:
            if fnmatch.fnmatch(required_action.lower(), action.lower()):
                return True
        return False


    def _resource_matches(self, resource_set, required_resource):
        if required_resource is None:
            return True

        for resource in resource_set:
            if fnmatch.fnmatch(required_resource, resource):
                return True
        return False

    # -------------------------
    # Permission evaluation
    # -------------------------
    def is_allowed(self, principal_name: str, action: str, resource: str = None) -> bool:

        principal = self.principals[principal_name]

        explicit_deny = False
        allow = False

        for stmt in principal.policy_statements:

            if not self._action_matches(stmt.actions, action):
                continue

            if not self._resource_matches(stmt.resources, resource):
                continue

            if stmt.effect == "Deny":
                explicit_deny = True

            if stmt.effect == "Allow":
                allow = True

        if explicit_deny:
            return False

        return allow
    # -------------------------
    # Role assumption semantics
    # -------------------------
    def can_assume(self, principal_name: str, role_name: str) -> bool:

        principal = self.principals[principal_name]
        role = self.principals[role_name]

        if role.type != "role":
            return False

        role_arn = getattr(role, "arn", role_name)

        # Must have sts:AssumeRole on this role
        if not self.is_allowed(principal_name, "sts:AssumeRole", resource=role_arn):
            return False

        # Normalize ARN → name
        for trusted in role.trusts:
            if trusted.endswith(f"/{principal_name}") or trusted == principal_name:
                return True

        return False

    # -------------------------
    # PassRole semantics
    # -------------------------
    def can_pass_role(self, principal_name: str, role_name: str) -> bool:
        role = self.principals[role_name]
        role_arn = getattr(role, "arn", role_name)

        return self.is_allowed(principal_name, "iam:PassRole", resource=role_arn)