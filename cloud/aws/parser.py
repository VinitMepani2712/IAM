import json
import os
from core.entities import Principal, PolicyStatement, TrustCondition


def _ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def _stmt_to_policy_statement(stmt: dict) -> PolicyStatement:
    actions   = _ensure_list(stmt.get("Action", []))
    resources = _ensure_list(stmt.get("Resource", "*")) or ["*"]
    return PolicyStatement(
        effect=stmt.get("Effect", "Deny"),
        actions=set(actions),
        resources=set(resources)
    )


def _parse_condition(condition_block: dict) -> TrustCondition:
    """
    Parse a Condition block from an AssumeRolePolicyDocument statement.

    Detects:
      - aws:MultiFactorAuthPresent: "true"  → requires_mfa
      - sts:ExternalId                       → requires_external_id
    """
    if not condition_block:
        return TrustCondition()

    requires_mfa         = False
    requires_external_id = False
    external_id_value    = None

    for operator, conditions in condition_block.items():
        op = operator.lower()
        for key, value in (conditions or {}).items():
            key_l = key.lower()

            # MFA check — BoolIfExists or Bool operator
            if key_l == "aws:multifactorauthpresent":
                if str(value).lower() == "true":
                    requires_mfa = True

            # ExternalId check
            if key_l == "sts:externalid":
                requires_external_id = True
                external_id_value    = str(value) if value else None

    return TrustCondition(
        requires_mfa=requires_mfa,
        requires_external_id=requires_external_id,
        external_id_value=external_id_value,
        raw=condition_block,
    )


def _extract_trusts_and_conditions(assume_doc: dict):
    """
    Returns:
        trusts:     set of trusted principal ARNs/names
        conditions: dict[trusted_principal → TrustCondition]
    """
    trusts     = set()
    conditions = {}

    for stmt in assume_doc.get("Statement", []) or []:
        if stmt.get("Effect") != "Allow":
            continue

        principal   = stmt.get("Principal", {}) or {}
        cond_block  = stmt.get("Condition", {}) or {}
        tc          = _parse_condition(cond_block)

        aws_val = principal.get("AWS")
        if aws_val:
            for item in _ensure_list(aws_val):
                trusts.add(item)
                if tc.has_any():
                    conditions[item] = tc

        svc_val = principal.get("Service")
        if svc_val:
            for item in _ensure_list(svc_val):
                trusts.add(item)
                if tc.has_any():
                    conditions[item] = tc

    return trusts, conditions


# Keep legacy function for backward compatibility
def _extract_trusts_from_assume_doc(assume_doc: dict) -> set:
    trusts, _ = _extract_trusts_and_conditions(assume_doc)
    return trusts


def parse_aws_iam_json(source):

    # ── Load JSON ─────────────────────────────────────────────────────────────
    if isinstance(source, str):
        if not os.path.exists(source):
            raise FileNotFoundError(f"File not found: {source}")
        with open(source, "r") as f:
            data = json.load(f)
    else:
        data = source

    principals = {}

    # ── FORMAT A: AWS GetAccountAuthorizationDetails ──────────────────────────
    if "UserDetailList" in data or "RoleDetailList" in data:

        # Users
        for user in data.get("UserDetailList", []) or []:
            name       = user["UserName"]
            arn        = user.get("Arn")
            account_id = arn.split(":")[4] if arn and ":" in arn else "default"

            statements = []
            for policy in user.get("UserPolicyList", []) or []:
                doc = policy.get("PolicyDocument", {}) or {}
                for stmt in doc.get("Statement", []) or []:
                    statements.append(_stmt_to_policy_statement(stmt))

            principals[name] = Principal(
                name=name, account_id=account_id, type="user",
                policy_statements=statements, trusts=set(), arn=arn
            )

        # Roles
        for role in data.get("RoleDetailList", []) or []:
            name       = role["RoleName"]
            arn        = role.get("Arn")
            account_id = arn.split(":")[4] if arn and ":" in arn else "default"

            assume_doc = role.get("AssumeRolePolicyDocument", {}) or {}
            trusts, trust_conditions = _extract_trusts_and_conditions(assume_doc)

            statements = []
            for policy in role.get("RolePolicyList", []) or []:
                doc = policy.get("PolicyDocument", {}) or {}
                for stmt in doc.get("Statement", []) or []:
                    statements.append(_stmt_to_policy_statement(stmt))

            principal_obj = Principal(
                name=name, account_id=account_id, type="role",
                policy_statements=statements, trusts=trusts, arn=arn,
                trust_conditions=trust_conditions,
            )
            principal_obj.attached_managed_policies = role.get("AttachedManagedPolicies", [])
            principals[name] = principal_obj

        return principals

    # ── FORMAT B: Enterprise Simulation ──────────────────────────────────────
    if "Accounts" in data and isinstance(data["Accounts"], list):

        for acct in data["Accounts"]:
            account_id = str(acct.get("AccountId", "default"))

            for u in acct.get("Users", []) or []:
                name = u["UserName"]
                arn  = u.get("Arn") or f"arn:aws:iam::{account_id}:user/{name}"
                statements = []
                for pol in u.get("AttachedPolicies", []) or []:
                    for stmt in (pol.get("Document") or {}).get("Statement", []) or []:
                        statements.append(_stmt_to_policy_statement(stmt))
                principals[name] = Principal(
                    name=name, account_id=account_id, type="user",
                    policy_statements=statements, trusts=set(), arn=arn
                )

            for r in acct.get("Roles", []) or []:
                name       = r["RoleName"]
                arn        = r.get("Arn") or f"arn:aws:iam::{account_id}:role/{name}"
                assume_doc = r.get("AssumeRolePolicyDocument", {}) or {}
                trusts, trust_conditions = _extract_trusts_and_conditions(assume_doc)
                statements = []
                for pol in r.get("AttachedPolicies", []) or []:
                    for stmt in (pol.get("Document") or {}).get("Statement", []) or []:
                        statements.append(_stmt_to_policy_statement(stmt))
                principals[name] = Principal(
                    name=name, account_id=account_id, type="role",
                    policy_statements=statements, trusts=trusts, arn=arn,
                    trust_conditions=trust_conditions,
                )

        return principals

    raise ValueError("Unsupported IAM JSON format.")