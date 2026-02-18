# Define truly high-impact IAM actions

CRITICAL_ACTIONS = {
    "AdministratorAccess",
    "iam:CreatePolicy",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreateUser",
    "iam:CreateAccessKey"
}


def is_critical_action(action: str) -> bool:
    for critical in CRITICAL_ACTIONS:
        if critical.endswith("*"):
            if action.startswith(critical[:-1]):
                return True
        if action == critical:
            return True
    return False
