from dataclasses import dataclass, field
from typing import List, Set, Dict, Optional


@dataclass
class PolicyStatement:
    effect: str
    actions: Set[str]
    resources: Set[str]


@dataclass
class TrustCondition:
    """
    Represents a Condition block parsed from an AssumeRolePolicyDocument statement.

    Fields:
        requires_mfa        — True if aws:MultiFactorAuthPresent: "true" is present
        requires_external_id — True if sts:ExternalId condition is present
        external_id_value   — the actual ExternalId value if specified
        raw                 — full raw condition dict for reference
    """
    requires_mfa:         bool = False
    requires_external_id: bool = False
    external_id_value:    Optional[str] = None
    raw:                  Dict = field(default_factory=dict)

    def has_any(self) -> bool:
        return self.requires_mfa or self.requires_external_id

    def summary(self) -> str:
        parts = []
        if self.requires_mfa:
            parts.append("MFA required")
        if self.requires_external_id:
            eid = f" ({self.external_id_value})" if self.external_id_value else ""
            parts.append(f"ExternalId required{eid}")
        return ", ".join(parts) if parts else "none"


@dataclass
class Principal:
    name: str
    account_id: str
    type: str   # "user" or "role"

    policy_statements: List[PolicyStatement] = field(default_factory=list)
    trusts: Set[str] = field(default_factory=set)
    arn: str = None

    attached_managed_policies: List[Dict] = field(default_factory=list)

    # Conditions parsed from AssumeRolePolicyDocument
    # Key: trust principal name/ARN → TrustCondition
    trust_conditions: Dict[str, "TrustCondition"] = field(default_factory=dict)

    def __hash__(self):
        return hash(self.name)