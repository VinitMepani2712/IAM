import json
import os
from core.entities import Principal, PolicyStatement


def _ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def _stmt_to_policy_statement(stmt: dict) -> PolicyStatement:
    actions = _ensure_list(stmt.get("Action", []))
    resources = _ensure_list(stmt.get("Resource", "*")) or ["*"]
    return PolicyStatement(
        effect=stmt.get("Effect", "Deny"),
        actions=set(actions),
        resources=set(resources)
    )


def _extract_trusts_from_assume_doc(assume_doc: dict) -> set:
    trusts = set()
    for stmt in assume_doc.get("Statement", []) or []:
        if stmt.get("Effect") != "Allow":
            continue

        principal = stmt.get("Principal", {}) or {}

        aws_val = principal.get("AWS")
        if aws_val:
            for item in _ensure_list(aws_val):
                trusts.add(item)

        svc_val = principal.get("Service")
        if svc_val:
            for item in _ensure_list(svc_val):
                trusts.add(item)

    return trusts


def parse_aws_iam_json(source):

    # -----------------------------
    # Load JSON
    # -----------------------------
    if isinstance(source, str):
        if not os.path.exists(source):
            raise FileNotFoundError(f"File not found: {source}")
        with open(source, "r") as f:
            data = json.load(f)
    else:
        data = source

    principals = {}

    # ============================================================
    # FORMAT A: AWS GetAccountAuthorizationDetails
    # ============================================================
    if "UserDetailList" in data or "RoleDetailList" in data:

        # -----------------------------
        # Users
        # -----------------------------
        for user in data.get("UserDetailList", []) or []:

            name = user["UserName"]
            arn = user.get("Arn")
            account_id = arn.split(":")[4] if arn and ":" in arn else "default"

            statements = []
            for policy in user.get("UserPolicyList", []) or []:
                doc = policy.get("PolicyDocument", {}) or {}
                for stmt in doc.get("Statement", []) or []:
                    statements.append(_stmt_to_policy_statement(stmt))

            principals[name] = Principal(
                name=name,
                account_id=account_id,
                type="user",
                policy_statements=statements,
                trusts=set(),
                arn=arn
            )

        # -----------------------------
        # Roles
        # -----------------------------
        for role in data.get("RoleDetailList", []) or []:

            name = role["RoleName"]
            arn = role.get("Arn")
            account_id = arn.split(":")[4] if arn and ":" in arn else "default"

            # Trust relationships
            trusts = _extract_trusts_from_assume_doc(
                role.get("AssumeRolePolicyDocument", {}) or {}
            )

            # Inline policies
            statements = []
            for policy in role.get("RolePolicyList", []) or []:
                doc = policy.get("PolicyDocument", {}) or {}
                for stmt in doc.get("Statement", []) or []:
                    statements.append(_stmt_to_policy_statement(stmt))

            principal_obj = Principal(
                name=name,
                account_id=account_id,
                type="role",
                policy_statements=statements,
                trusts=trusts,
                arn=arn
            )

            # 🔥 Store attached managed policies (CRITICAL FIX)
            principal_obj.attached_managed_policies = role.get(
                "AttachedManagedPolicies", []
            )

            principals[name] = principal_obj

        return principals

    # ============================================================
    # FORMAT B: Enterprise Simulation
    # ============================================================
    if "Accounts" in data and isinstance(data["Accounts"], list):

        for acct in data["Accounts"]:
            account_id = str(acct.get("AccountId", "default"))

            # Users
            for u in acct.get("Users", []) or []:
                name = u["UserName"]
                arn = u.get("Arn") or f"arn:aws:iam::{account_id}:user/{name}"

                statements = []
                for pol in u.get("AttachedPolicies", []) or []:
                    doc = (pol.get("Document") or {})
                    for stmt in doc.get("Statement", []) or []:
                        statements.append(_stmt_to_policy_statement(stmt))

                principals[name] = Principal(
                    name=name,
                    account_id=account_id,
                    type="user",
                    policy_statements=statements,
                    trusts=set(),
                    arn=arn
                )

            # Roles
            for r in acct.get("Roles", []) or []:
                name = r["RoleName"]
                arn = r.get("Arn") or f"arn:aws:iam::{account_id}:role/{name}"

                trusts = _extract_trusts_from_assume_doc(
                    r.get("AssumeRolePolicyDocument", {}) or {}
                )

                statements = []
                for pol in r.get("AttachedPolicies", []) or []:
                    doc = (pol.get("Document") or {})
                    for stmt in doc.get("Statement", []) or []:
                        statements.append(_stmt_to_policy_statement(stmt))

                principals[name] = Principal(
                    name=name,
                    account_id=account_id,
                    type="role",
                    policy_statements=statements,
                    trusts=trusts,
                    arn=arn
                )

        return principals

    # Unsupported format
    raise ValueError(
        "Unsupported IAM JSON format."
    )