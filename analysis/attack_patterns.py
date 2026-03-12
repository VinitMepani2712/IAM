def classify_attack_pattern(path, cross_account):
    """
    Classify an escalation path into one or more MITRE ATT&CK-mapped patterns.

    Changes from v1:
    - Multi-hop threshold lowered: 3+ hops (was >5) — catches real 4-hop chains
    - Added PERSISTENCE_VIA_ACCESS_KEY pattern
    - Added IDENTITY_CREATION pattern
    - Fixed PRIVILEGE_AMPLIFICATION to match actual capability node names
    - Patterns now accumulate correctly (cross-account + multi-hop can both fire)
    """

    patterns = []
    actions = [node for node in path if node.startswith("ACTION::")]
    action_names = [a.split("::")[1] for a in actions]
    capability = path[-1].split("::")[1] if path[-1].startswith("CAPABILITY::") else None
    hop_count = len(path)

    # ── 1. PassRole + Compute Execution ──────────────────────────────────────
    if any("iam:PassRole" in a for a in action_names) and \
       any(x in action_names for x in ["ec2:RunInstances", "lambda:CreateFunction",
                                        "ecs:RunTask", "iam:PassRole+ec2:RunInstances",
                                        "iam:PassRole+lambda:CreateFunction"]):
        patterns.append({
            "pattern": "PASSROLE_COMPUTE_EXECUTION",
            "mitre": "T1098.001 - Account Manipulation: Additional Cloud Credentials"
        })

    # ── 2. Policy Manipulation ────────────────────────────────────────────────
    if any(x in action_names for x in [
        "iam:AttachRolePolicy", "iam:PutRolePolicy",
        "iam:AttachUserPolicy", "iam:PutUserPolicy"
    ]):
        patterns.append({
            "pattern": "POLICY_MANIPULATION",
            "mitre": "T1098 - Account Manipulation"
        })

    # ── 3. Privilege Amplification (wildcard / admin capability) ─────────────
    # Fixed: was checking wrong capability names
    if capability in ["FULL_ADMIN", "PRIVILEGE_PROPAGATION"]:
        patterns.append({
            "pattern": "PRIVILEGE_AMPLIFICATION",
            "mitre": "T1078.004 - Valid Accounts: Cloud Accounts"
        })

    # ── 4. Persistence via Access Key ────────────────────────────────────────
    if capability == "ACCESS_KEY_PERSISTENCE" or \
       any("iam:CreateAccessKey" in a for a in action_names):
        patterns.append({
            "pattern": "PERSISTENCE_VIA_ACCESS_KEY",
            "mitre": "T1098.001 - Account Manipulation: Additional Cloud Credentials"
        })

    # ── 5. Identity Creation ─────────────────────────────────────────────────
    if capability == "IDENTITY_CREATION" or \
       any(x in action_names for x in ["iam:CreateUser", "iam:CreateLoginProfile",
                                        "iam:UpdateLoginProfile"]):
        patterns.append({
            "pattern": "IDENTITY_CREATION_ABUSE",
            "mitre": "T1136.003 - Create Account: Cloud Account"
        })

    # ── 6. Cross-Account Lateral Movement ────────────────────────────────────
    if cross_account:
        patterns.append({
            "pattern": "CROSS_ACCOUNT_PIVOT",
            "mitre": "T1021.007 - Remote Services: Cloud Services"
        })

    # ── 7. Multi-Hop Escalation Chain ────────────────────────────────────────
    # FIX: lowered threshold from >5 to >3 — real 4-hop chains were missed
    if hop_count > 3:
        patterns.append({
            "pattern": "MULTI_HOP_LATERAL_MOVEMENT",
            "mitre": "T1021.007 - Remote Services: Cloud Services"
        })

    # ── 8. Pure Role Assumption (fallback) ───────────────────────────────────
    if not patterns and any("sts:AssumeRole" in a for a in action_names):
        patterns.append({
            "pattern": "ROLE_ASSUMPTION_ABUSE",
            "mitre": "T1078.004 - Valid Accounts: Cloud Accounts"
        })

    if not patterns:
        patterns.append({
            "pattern": "GENERIC_ESCALATION",
            "mitre": "T1078.004 - Valid Accounts: Cloud Accounts"
        })

    return patterns