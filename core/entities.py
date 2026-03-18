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
        requires_mfa         — True if aws:MultiFactorAuthPresent: "true" is present
        requires_external_id — True if sts:ExternalId condition is present
        external_id_value    — the actual ExternalId value if specified
        source_ip_restricted — True if aws:SourceIp / aws:SourceVpc condition is present
        org_id_required      — True if aws:PrincipalOrgID condition is present
        region_restricted    — True if aws:RequestedRegion condition is present
        raw                  — full raw condition dict for reference
    """
    requires_mfa:         bool = False
    requires_external_id: bool = False
    external_id_value:    Optional[str] = None
    source_ip_restricted: bool = False
    org_id_required:      bool = False
    region_restricted:    bool = False
    raw:                  Dict = field(default_factory=dict)

    def has_any(self) -> bool:
        return (self.requires_mfa or self.requires_external_id or
                self.source_ip_restricted or self.org_id_required or self.region_restricted)

    def summary(self) -> str:
        parts = []
        if self.requires_mfa:
            parts.append("MFA required")
        if self.requires_external_id:
            eid = f" ({self.external_id_value})" if self.external_id_value else ""
            parts.append(f"ExternalId required{eid}")
        if self.source_ip_restricted:
            parts.append("Source IP restricted")
        if self.org_id_required:
            parts.append("Org ID required")
        if self.region_restricted:
            parts.append("Region restricted")
        return ", ".join(parts) if parts else "none"


@dataclass
class SCPStatement:
    """
    A Service Control Policy that applies to all principals in an account.
    Acts as an org-level deny layer — if an SCP denies an action, no principal
    in that account can perform it regardless of their IAM permissions.
    """
    account_id: str  # account this SCP applies to, or "*" for all accounts
    statements: List[PolicyStatement] = field(default_factory=list)


@dataclass
class ResourcePolicy:
    """
    A resource-based policy attached to an AWS resource (Lambda, S3, SQS, etc.).

    resource_arn      — ARN of the resource
    resource_type     — "lambda", "s3", "sqs", "secretsmanager", etc.
    execution_role    — for Lambda/ECS: the IAM role the resource executes with
    allowed_principals — set of principal ARNs that have Allow access
    allowed_actions    — set of actions granted by Allow statements
    """
    resource_arn:       str
    resource_type:      str
    execution_role:     Optional[str] = None
    allowed_principals: Set[str]      = field(default_factory=set)
    allowed_actions:    Set[str]      = field(default_factory=set)


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

    # Permission boundary — limits the maximum permissions a principal can have.
    # If set, only actions ALLOWED by both the identity policy AND the boundary
    # are effective. Stored as a list of PolicyStatements (Allow only).
    permission_boundary: List["PolicyStatement"] = field(default_factory=list)

    def __hash__(self):
        return hash(self.name)