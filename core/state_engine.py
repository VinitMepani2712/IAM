"""
core/state_engine.py
IAM State Engine — tracks which capabilities a principal has reached.

Used as a cache layer during graph traversal so the reachability module
can quickly ask "does this principal already hold capability X?" without
re-scanning every PolicyStatement on every path iteration.
"""


class IAMStateEngine:
    """
    Tracks direct IAM capability ownership for every principal in an environment.

    Usage:
        engine = IAMStateEngine(principals)
        caps = engine.get_direct_capabilities("UserA")
        if engine.is_escalation("UserA", "FULL_ADMIN"):
            ...
        engine.reset()  # clear cache between runs
    """

    def __init__(self, principals: dict):
        self._principals = principals
        self._cache: dict = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_direct_capabilities(self, principal_name: str) -> set:
        """Return the set of capability classes the principal directly holds."""
        if principal_name in self._cache:
            return self._cache[principal_name]

        from core.privilege_model import classify_action

        caps = set()
        principal = self._principals.get(principal_name)
        if principal:
            for stmt in principal.policy_statements:
                if stmt.effect == "Allow":
                    for action in stmt.actions:
                        cap = classify_action(action)
                        if cap:
                            caps.add(cap)

        self._cache[principal_name] = caps
        return caps

    def is_escalation(self, principal_name: str, target_capability: str) -> bool:
        """
        Return True if reaching `target_capability` is an escalation for
        this principal (i.e. they do not already directly hold it).
        """
        return target_capability not in self.get_direct_capabilities(principal_name)

    def principals_without_capability(self, capability: str) -> list:
        """Return all principal names that do NOT directly hold `capability`."""
        return [
            name for name in self._principals
            if self.is_escalation(name, capability)
        ]

    def reset(self):
        """Clear the capability cache (call between independent analysis runs)."""
        self._cache.clear()
