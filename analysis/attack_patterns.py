def classify_attack_pattern(path, cross_account):

    patterns = []
    actions = [node for node in path if node.startswith("ACTION::")]
    action_names = [a.split("::")[1] for a in actions]

    capability = path[-1].split("::")[1] if path[-1].startswith("CAPABILITY::") else None
    hop_count = len(path)

    # ---------------------------------------------------
    # 1️⃣ PassRole + Compute Execution
    # ---------------------------------------------------
    if any("iam:PassRole" in a for a in action_names) and \
       any(x in action_names for x in ["ec2:RunInstances", "lambda:CreateFunction", "ecs:RunTask"]):

        patterns.append({
            "pattern": "PASSROLE_COMPUTE_EXECUTION",
            "mitre": "T1098 - Account Manipulation"
        })

    # ---------------------------------------------------
    # 2️⃣ Policy Modification Abuse
    # ---------------------------------------------------
    if any(x in action_names for x in [
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy"
    ]):
        patterns.append({
            "pattern": "POLICY_MANIPULATION",
            "mitre": "T1098 - Account Manipulation"
        })

    # ---------------------------------------------------
    # 3️⃣ Wildcard Privilege Amplification
    # ---------------------------------------------------
    if capability in ["ADMIN_ACCESS", "FULL_ACCESS"]:
        patterns.append({
            "pattern": "PRIVILEGE_AMPLIFICATION",
            "mitre": "T1078 - Valid Accounts"
        })

    # ---------------------------------------------------
    # 4️⃣ Cross-Account Lateral Movement
    # ---------------------------------------------------
    if cross_account:
        patterns.append({
            "pattern": "CROSS_ACCOUNT_PIVOT",
            "mitre": "T1021 - Remote Services"
        })

    # ---------------------------------------------------
    # 5️⃣ Multi-Hop Escalation Chain
    # ---------------------------------------------------
    if hop_count > 5:
        patterns.append({
            "pattern": "MULTI_HOP_LATERAL_MOVEMENT",
            "mitre": "T1021 - Remote Services"
        })

    # ---------------------------------------------------
    # 6️⃣ Pure Role Assumption (Fallback)
    # ---------------------------------------------------
    if not patterns and any("sts:AssumeRole" in a for a in action_names):
        patterns.append({
            "pattern": "ROLE_ASSUMPTION_ABUSE",
            "mitre": "T1078 - Valid Accounts"
        })

    if not patterns:
        patterns.append({
            "pattern": "GENERIC_ESCALATION",
            "mitre": "T1078 - Valid Accounts"
        })

    return patterns