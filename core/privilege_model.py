CAPABILITY_MAP = {
    # Direct admin
    "AdministratorAccess": "FULL_ADMIN",

    # Role abuse
    "sts:AssumeRole": "ROLE_ASSUMPTION",
    "iam:PassRole": "PRIVILEGE_PROPAGATION",

    # Policy manipulation
    "iam:AttachRolePolicy": "POLICY_MODIFICATION",
    "iam:PutRolePolicy": "POLICY_MODIFICATION",

    # Persistence
    "iam:CreateAccessKey": "ACCESS_KEY_PERSISTENCE",

    # Compute abuse
    "ec2:RunInstances": "COMPUTE_LAUNCH",

    # Identity abuse
    "iam:CreateUser": "IDENTITY_CREATION"
}

CAPABILITY_WEIGHTS = {
    "FULL_ADMIN": 10,
    "POLICY_MODIFICATION": 8,
    "PRIVILEGE_PROPAGATION": 7,
    "ACCESS_KEY_PERSISTENCE": 7,
    "ROLE_ASSUMPTION": 6,
    "COMPUTE_LAUNCH": 6,
    "IDENTITY_CREATION": 6
}

def classify_action(action):
    return CAPABILITY_MAP.get(action)
