import json
import os
from core.entities import Principal, PolicyStatement, TrustCondition, SCPStatement, ResourcePolicy


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
      - aws:SourceIp / aws:SourceVpc         → source_ip_restricted
      - aws:PrincipalOrgID                   → org_id_required
      - aws:RequestedRegion                  → region_restricted
    """
    if not condition_block:
        return TrustCondition()

    requires_mfa         = False
    requires_external_id = False
    external_id_value    = None
    source_ip_restricted = False
    org_id_required      = False
    region_restricted    = False

    for _, conditions in condition_block.items():
        for key, value in (conditions or {}).items():
            key_l = key.lower()

            # MFA check — BoolIfExists or Bool operator
            if key_l == "aws:multifactorauthpresent":
                if str(value).lower() == "true":
                    requires_mfa = True

            # ExternalId check
            elif key_l == "sts:externalid":
                requires_external_id = True
                external_id_value    = str(value) if value else None

            # Source IP / VPC restriction
            elif key_l in ("aws:sourceip", "aws:sourcevpc", "aws:sourcevpce"):
                source_ip_restricted = True

            # Org ID requirement (restricts to principals within the org)
            elif key_l == "aws:principalorgid":
                org_id_required = True

            # Region restriction
            elif key_l == "aws:requestedregion":
                region_restricted = True

    return TrustCondition(
        requires_mfa=requires_mfa,
        requires_external_id=requires_external_id,
        external_id_value=external_id_value,
        source_ip_restricted=source_ip_restricted,
        org_id_required=org_id_required,
        region_restricted=region_restricted,
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


def _parse_boundary_doc(doc: dict) -> list:
    """Parse a permission boundary PolicyDocument into PolicyStatement objects."""
    statements = []
    for stmt in (doc or {}).get("Statement", []) or []:
        ps = _stmt_to_policy_statement(stmt)
        if ps.effect == "Allow":          # boundaries only grant via Allow stmts
            statements.append(ps)
    return statements


def _parse_all_stmts(doc: dict) -> list:
    """Parse ALL statements (Allow and Deny) from a PolicyDocument."""
    return [_stmt_to_policy_statement(s) for s in (doc or {}).get("Statement", []) or []]


def _build_policy_map(policies_list: list) -> dict:
    """
    Build ARN → List[PolicyStatement] from the top-level Policies array
    in GetAccountAuthorizationDetails.

    Includes ALL statements (Allow + Deny) so the map can be used both
    for resolving attached managed policies on principals AND for
    permission boundary resolution (caller filters to Allow as needed).
    """
    policy_map = {}
    for pol in policies_list or []:
        arn = pol.get("Arn")
        if not arn:
            continue
        for version in pol.get("PolicyVersionList", []) or []:
            if version.get("IsDefaultVersion"):
                doc = version.get("Document", {}) or {}
                policy_map[arn] = _parse_all_stmts(doc)
                break
    return policy_map


def _build_group_map(group_list: list, policy_map: dict) -> dict:
    """
    Build group_name → List[PolicyStatement] from GroupDetailList.

    Resolves both inline group policies (GroupPolicyList) and attached
    managed policies (AttachedManagedPolicies) via policy_map.
    """
    group_map = {}
    for grp in group_list or []:
        name       = grp.get("GroupName") or grp.get("Group", {}).get("GroupName")
        if not name:
            continue
        stmts = []
        # Inline policies
        for pol in grp.get("GroupPolicyList", []) or []:
            doc = pol.get("PolicyDocument", {}) or {}
            for stmt in doc.get("Statement", []) or []:
                stmts.append(_stmt_to_policy_statement(stmt))
        # Attached managed policies
        for ap in grp.get("AttachedManagedPolicies", []) or []:
            arn = ap.get("PolicyArn", "")
            if arn in policy_map:
                stmts.extend(policy_map[arn])
        group_map[name] = stmts
    return group_map


def _parse_scps(scp_list: list) -> list:
    """
    Parse a list of SCP dicts into SCPStatement objects.

    Expected format per entry:
        {
            "AccountId": "*",          # optional, defaults to "*"
            "PolicyDocument": {
                "Statement": [ ... ]   # standard policy statement format
            }
        }
    """
    scps = []
    for entry in scp_list or []:
        account_id = str(entry.get("AccountId", "*"))
        doc        = entry.get("PolicyDocument", {}) or {}
        statements = []
        for stmt in doc.get("Statement", []) or []:
            statements.append(_stmt_to_policy_statement(stmt))
        if statements:
            scps.append(SCPStatement(account_id=account_id, statements=statements))
    return scps


def _parse_resource_policies(rp_list: list) -> list:
    """
    Parse a ResourcePolicies array into ResourcePolicy objects.

    Expected entry format:
        {
            "ResourceArn":      "arn:aws:lambda:us-east-1:123456789012:function:MyFunc",
            "ResourceType":     "lambda",          # lambda | s3 | sqs | secretsmanager
            "ExecutionRoleArn": "arn:...:role/X",  # for Lambda/ECS only
            "PolicyDocument":   { "Statement": [...] }
        }
    """
    result = []
    for entry in rp_list or []:
        arn          = entry.get("ResourceArn", "")
        rtype        = (entry.get("ResourceType") or "").lower()
        exec_role    = entry.get("ExecutionRoleArn") or entry.get("ExecutionRole")
        doc          = entry.get("PolicyDocument", {}) or {}
        allowed_principals: set = set()
        allowed_actions:    set = set()

        for stmt in doc.get("Statement", []) or []:
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {}) or {}
            actions   = _ensure_list(stmt.get("Action", []))

            # Collect principals (AWS, Federated, Service)
            for p_key in ("AWS", "Federated", "Service"):
                for item in _ensure_list(principal.get(p_key)):
                    allowed_principals.add(item)
            if principal == "*":
                allowed_principals.add("*")

            for action in actions:
                allowed_actions.add(action.lower())

        if allowed_principals:
            result.append(ResourcePolicy(
                resource_arn=arn,
                resource_type=rtype,
                execution_role=exec_role,
                allowed_principals=allowed_principals,
                allowed_actions=allowed_actions,
            ))
    return result


def parse_aws_iam_json(source):
    """
    Parse IAM JSON and return (principals, scps).

    principals — dict[name → Principal]
    scps       — list[SCPStatement]  (empty list if no SCPs in the file)
    """

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

        # Build ARN → statements map for managed policy + boundary resolution
        policy_map = _build_policy_map(data.get("Policies", []))

        # Build group_name → statements map for group membership resolution
        group_map = _build_group_map(data.get("GroupDetailList", []), policy_map)

        # Users
        for user in data.get("UserDetailList", []) or []:
            name       = user["UserName"]
            arn        = user.get("Arn")
            account_id = arn.split(":")[4] if arn and ":" in arn else "default"

            statements = []
            # Inline policies
            for policy in user.get("UserPolicyList", []) or []:
                doc = policy.get("PolicyDocument", {}) or {}
                for stmt in doc.get("Statement", []) or []:
                    statements.append(_stmt_to_policy_statement(stmt))
            # Attached managed policies — resolve full document from policy_map
            for ap in user.get("AttachedManagedPolicies", []) or []:
                ap_arn = ap.get("PolicyArn", "")
                if ap_arn in policy_map:
                    statements.extend(policy_map[ap_arn])
            # Group membership — inherit all policies from each group the user belongs to
            for group_name in user.get("GroupList", []) or []:
                statements.extend(group_map.get(group_name, []))

            # Permission boundary (Allow-only filter)
            boundary_stmts = []
            pb = user.get("PermissionsBoundary", {}) or {}
            pb_arn = pb.get("PermissionsBoundaryArn", "")
            if pb_arn and pb_arn in policy_map:
                boundary_stmts = [s for s in policy_map[pb_arn] if s.effect == "Allow"]
            elif pb.get("PermissionsBoundaryDocument"):
                boundary_stmts = _parse_boundary_doc(pb["PermissionsBoundaryDocument"])

            p = Principal(
                name=name, account_id=account_id, type="user",
                policy_statements=statements, trusts=set(), arn=arn,
            )
            p.permission_boundary = boundary_stmts
            principals[name] = p

        # Roles
        for role in data.get("RoleDetailList", []) or []:
            name       = role["RoleName"]
            arn        = role.get("Arn")
            account_id = arn.split(":")[4] if arn and ":" in arn else "default"

            assume_doc = role.get("AssumeRolePolicyDocument", {}) or {}
            trusts, trust_conditions = _extract_trusts_and_conditions(assume_doc)

            statements = []
            # Inline policies
            for policy in role.get("RolePolicyList", []) or []:
                doc = policy.get("PolicyDocument", {}) or {}
                for stmt in doc.get("Statement", []) or []:
                    statements.append(_stmt_to_policy_statement(stmt))
            # Attached managed policies — resolve full document from policy_map
            for ap in role.get("AttachedManagedPolicies", []) or []:
                arn = ap.get("PolicyArn", "")
                if arn in policy_map:
                    statements.extend(policy_map[arn])

            # Permission boundary (Allow-only filter)
            boundary_stmts = []
            pb = role.get("PermissionsBoundary", {}) or {}
            pb_arn = pb.get("PermissionsBoundaryArn", "")
            if pb_arn and pb_arn in policy_map:
                boundary_stmts = [s for s in policy_map[pb_arn] if s.effect == "Allow"]
            elif pb.get("PermissionsBoundaryDocument"):
                boundary_stmts = _parse_boundary_doc(pb["PermissionsBoundaryDocument"])

            principal_obj = Principal(
                name=name, account_id=account_id, type="role",
                policy_statements=statements, trusts=trusts, arn=arn,
                trust_conditions=trust_conditions,
            )
            principal_obj.attached_managed_policies = role.get("AttachedManagedPolicies", [])
            principal_obj.permission_boundary = boundary_stmts
            principals[name] = principal_obj

        scps             = _parse_scps(data.get("ServiceControlPolicies", []))
        resource_policies = _parse_resource_policies(data.get("ResourcePolicies", []))
        return principals, scps, resource_policies

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

        # Top-level SCPs apply to all accounts in the simulation
        scps             = _parse_scps(data.get("ServiceControlPolicies", []))
        resource_policies = _parse_resource_policies(data.get("ResourcePolicies", []))
        return principals, scps, resource_policies

    raise ValueError("Unsupported IAM JSON format.")