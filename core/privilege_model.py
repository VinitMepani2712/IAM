# ─────────────────────────────────────────────────────────────────────────────
# Capability map: IAM action → capability class
#
# Added in Tier 1:
#   iam:CreateLoginProfile   → CONSOLE_ACCESS    (create password for existing user)
#   iam:UpdateLoginProfile   → CONSOLE_ACCESS    (reset another user's password)
#   iam:AttachUserPolicy     → POLICY_MODIFICATION (was missing from graph)
#   iam:PutUserPolicy        → POLICY_MODIFICATION (was missing from graph)
#   sts:AssumeRoleWithWebIdentity → ROLE_ASSUMPTION (federated identity pivot)
#   lambda:CreateFunction    → COMPUTE_LAUNCH    (was missing direct mapping)
# ─────────────────────────────────────────────────────────────────────────────

CAPABILITY_MAP = {
    # Direct admin
    "AdministratorAccess":          "FULL_ADMIN",

    # Role abuse
    "sts:AssumeRole":               "ROLE_ASSUMPTION",
    "sts:AssumeRoleWithWebIdentity":"ROLE_ASSUMPTION",   # NEW — federated pivot

    # Privilege propagation
    "iam:PassRole":                 "PRIVILEGE_PROPAGATION",

    # Policy manipulation
    "iam:AttachRolePolicy":             "POLICY_MODIFICATION",
    "iam:PutRolePolicy":                "POLICY_MODIFICATION",
    "iam:AttachUserPolicy":             "POLICY_MODIFICATION",
    "iam:PutUserPolicy":                "POLICY_MODIFICATION",
    "iam:CreatePolicyVersion":          "POLICY_MODIFICATION",
    "iam:SetDefaultPolicyVersion":      "POLICY_MODIFICATION",

    # Persistence
    "iam:CreateAccessKey":              "ACCESS_KEY_PERSISTENCE",

    # Console access takeover
    "iam:CreateLoginProfile":           "CONSOLE_ACCESS",
    "iam:UpdateLoginProfile":           "CONSOLE_ACCESS",

    # Compute abuse
    "ec2:RunInstances":                 "COMPUTE_LAUNCH",
    "lambda:CreateFunction":            "COMPUTE_LAUNCH",
    "lambda:UpdateFunctionCode":        "COMPUTE_LAUNCH",
    "glue:CreateJob":                   "COMPUTE_LAUNCH",
    "cloudformation:CreateStack":       "COMPUTE_LAUNCH",
    "ecs:RunTask":                      "COMPUTE_LAUNCH",
    "sagemaker:CreateTrainingJob":      "COMPUTE_LAUNCH",

    # Identity abuse
    "iam:CreateUser":                   "IDENTITY_CREATION",
    "iam:CreateRole":                   "IDENTITY_CREATION",

    # Privilege propagation
    "iam:AddUserToGroup":               "PRIVILEGE_PROPAGATION",
    "iam:UpdateAssumeRolePolicy":       "PRIVILEGE_PROPAGATION",
    "iam:DeleteRolePermissionsBoundary":"PRIVILEGE_PROPAGATION",
    "iam:DeleteUserPermissionsBoundary":"PRIVILEGE_PROPAGATION",

    # Low-impact — read/audit access (informational, reconnaissance value)
    "s3:GetObject":                 "DATA_READ",
    "s3:ListBucket":                "DATA_READ",
    "logs:GetLogEvents":            "LOG_ACCESS",
    "logs:DescribeLogGroups":       "LOG_ACCESS",
    "cloudtrail:LookupEvents":      "AUDIT_READ",
    "iam:ListRoles":                "RECON",
    "iam:GetRole":                  "RECON",
    "iam:SimulatePrincipalPolicy":  "RECON",
}

CAPABILITY_WEIGHTS = {
    "FULL_ADMIN":             10,
    "POLICY_MODIFICATION":     8,
    "PRIVILEGE_PROPAGATION":   7,
    "ACCESS_KEY_PERSISTENCE":  7,
    "CONSOLE_ACCESS":          7,
    "ROLE_ASSUMPTION":         6,
    "COMPUTE_LAUNCH":          6,
    "IDENTITY_CREATION":       6,
    # Low-impact
    "DATA_READ":               2,
    "LOG_ACCESS":              2,
    "AUDIT_READ":              3,
    "RECON":                   1,
}


def classify_action(action: str):
    return CAPABILITY_MAP.get(action)