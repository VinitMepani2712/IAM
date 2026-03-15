"""
cloud/aws/resource_model.py
AWS resource-based policy model.

Resource-based policies (S3 bucket policies, SQS queue policies, KMS key
policies, SNS topic policies, etc.) can grant cross-account access
independently of identity-based policies.  This module provides data
structures and a parser for those policies so they can be incorporated
into the attack graph.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class ResourcePolicy:
    """Represents a resource-based IAM policy attached to an AWS resource."""

    resource_arn:       str
    resource_type:      str             # e.g. "s3", "sqs", "kms", "sns"
    allowed_principals: Set[str] = field(default_factory=set)
    denied_principals:  Set[str] = field(default_factory=set)
    cross_account:      bool = False    # True when a foreign account is allowed
    public:             bool = False    # True when Principal is "*"
    raw_statements:     List[Dict] = field(default_factory=list)


def parse_resource_policy(resource_arn: str, policy_doc: Dict) -> ResourcePolicy:
    """
    Parse a raw resource-based policy document into a ResourcePolicy object.

    Args:
        resource_arn: ARN of the resource this policy is attached to.
        policy_doc:   Parsed JSON policy document (dict with "Statement" key).

    Returns:
        ResourcePolicy with extracted principals and access flags.
    """
    resource_type = _infer_resource_type(resource_arn)
    allowed:       Set[str] = set()
    denied:        Set[str] = set()
    public         = False
    cross_account  = False
    owner_account  = _extract_account(resource_arn)

    for stmt in policy_doc.get("Statement", []):
        effect    = stmt.get("Effect", "Allow")
        principal = stmt.get("Principal", {})

        if principal == "*" or principal == {"AWS": "*"}:
            public = True
            principals_set: Set[str] = {"*"}
        elif isinstance(principal, str):
            principals_set = {principal}
        elif isinstance(principal, dict):
            aws_p     = principal.get("AWS", [])
            service_p = principal.get("Service", [])
            if isinstance(aws_p, str):
                aws_p = [aws_p]
            if isinstance(service_p, str):
                service_p = [service_p]
            principals_set = set(aws_p) | set(service_p)
        else:
            principals_set = set()

        for p in principals_set:
            acc = _extract_account(p)
            if owner_account and acc and acc != owner_account:
                cross_account = True

        if effect == "Allow":
            allowed |= principals_set
        else:
            denied |= principals_set

    return ResourcePolicy(
        resource_arn=resource_arn,
        resource_type=resource_type,
        allowed_principals=allowed,
        denied_principals=denied,
        cross_account=cross_account,
        public=public,
        raw_statements=policy_doc.get("Statement", []),
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _infer_resource_type(arn: str) -> str:
    """Extract the service name from an ARN (e.g. 's3' from 'arn:aws:s3:::...')."""
    parts = arn.split(":")
    return parts[2] if len(parts) > 2 else "unknown"


def _extract_account(arn: str) -> Optional[str]:
    """Extract the 12-digit account ID from an ARN or return None."""
    parts = arn.split(":")
    if len(parts) >= 5 and parts[4].isdigit() and len(parts[4]) == 12:
        return parts[4]
    return None
