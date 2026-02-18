class IAMSemanticEvaluator:

    def __init__(self, principals: dict):
        """
        principals: dict[str, Principal]
        """
        self.principals = principals

    # -------------------------
    # Deny precedence handling
    # -------------------------
    def _matches(self, action_set, required_action):
        for action in action_set:
            if action == "*":
                return True
            if action.endswith("*"):
                if required_action.startswith(action[:-1]):
                    return True
            if action == required_action:
                return True
        return False

    def is_allowed(self, principal_name: str, action: str) -> bool:
        principal = self.principals[principal_name]

        # Explicit deny overrides
        if self._matches(principal.deny_actions, action):
            return False

        # Check allow
        return self._matches(principal.allow_actions, action)

    # -------------------------
    # Role assumption semantics
    # -------------------------
    def can_assume(self, principal_name: str, role_name: str) -> bool:
        principal = self.principals[principal_name]
        role = self.principals[role_name]

        if role.type != "role":
            return False

        # Must have sts:AssumeRole
        if not self.is_allowed(principal_name, "sts:AssumeRole"):
            return False

        # Role must trust principal
        if principal_name not in role.trusts:
            return False

        return True

    # -------------------------
    # PassRole semantics
    # -------------------------
    def can_pass_role(self, principal_name: str, role_name: str) -> bool:
        return self.is_allowed(principal_name, "iam:PassRole")
