"""
analysis/remediation_cli.py
Generate actionable AWS CLI commands and Terraform snippets for each
fix edge produced by compute_weighted_minimal_cut().

Usage:
    from analysis.remediation_cli import generate_cli_fixes
    fixes = generate_cli_fixes(recommended_fixes)
    # fixes is a list of dicts:
    # {
    #   "edge":        (src, dst),
    #   "description": "English one-liner",
    #   "cli":         "aws iam ...",
    #   "terraform":   "resource \"aws_iam_role_policy\" ...",
    # }
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple


# ── Helpers ───────────────────────────────────────────────────────────────────

def _strip(node: str) -> str:
    """Remove graph prefixes for display."""
    return (node.replace("CAPABILITY::", "")
               .replace("ACTION::", "")
               .replace("iam:PassRole+", "PassRole+"))


def _principal_name(node: str) -> str:
    """Best-effort extraction of a bare principal name from a graph node."""
    for prefix in ("ACTION::", "CAPABILITY::"):
        if node.startswith(prefix):
            return node
    return node


# ── Per-action CLI generators ─────────────────────────────────────────────────

def _fix_passrole(src: str) -> Dict[str, str]:
    principal = _principal_name(src)
    policy_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": "iam:PassRole",
            "Resource": "*"
        }]
    }, indent=2)
    return {
        "description": f"Restrict iam:PassRole on '{principal}' to specific approved role ARNs only",
        "cli": (
            f"# Option A — attach an inline deny policy\n"
            f"aws iam put-role-policy \\\n"
            f"  --role-name {principal} \\\n"
            f"  --policy-name DenyPassRole \\\n"
            f"  --policy-document '{policy_doc}'\n\n"
            f"# Option B — remove iam:PassRole from the existing managed policy via the console"
        ),
        "terraform": (
            f'resource "aws_iam_role_policy" "deny_pass_role_{principal}" {{\n'
            f'  name   = "DenyPassRole"\n'
            f'  role   = "{principal}"\n'
            f'  policy = jsonencode({{\n'
            f'    Version = "2012-10-17"\n'
            f'    Statement = [{{\n'
            f'      Effect   = "Deny"\n'
            f'      Action   = "iam:PassRole"\n'
            f'      Resource = "*"\n'
            f'    }}]\n'
            f'  }})\n'
            f'}}'
        ),
    }


def _fix_assumerole(src: str, dst: str) -> Dict[str, str]:
    """Fix a trust relationship edge (caller → role)."""
    role = dst if not dst.startswith("ACTION::") else dst.split("::")[-1]
    caller = _principal_name(src)
    return {
        "description": f"Remove '{caller}' from the trust policy of role '{role}'",
        "cli": (
            f"# Fetch current trust policy first:\n"
            f"aws iam get-role --role-name {role} "
            f"--query 'Role.AssumeRolePolicyDocument'\n\n"
            f"# Then update it with the principal removed:\n"
            f"aws iam update-assume-role-policy \\\n"
            f"  --role-name {role} \\\n"
            f"  --policy-document '<trust-policy-with-{caller}-removed>'"
        ),
        "terraform": (
            f'# In your aws_iam_role "{role}" resource, remove the\n'
            f'# assume_role_policy statement that allows "{caller}".'
        ),
    }


def _fix_policy_modification(src: str, action: str) -> Dict[str, str]:
    principal = _principal_name(src)
    policy_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Action": [
                "iam:AttachRolePolicy", "iam:DetachRolePolicy",
                "iam:PutRolePolicy", "iam:DeleteRolePolicy",
                "iam:AttachUserPolicy", "iam:PutUserPolicy"
            ],
            "Resource": "*"
        }]
    }, indent=2)
    return {
        "description": f"Remove IAM policy modification permissions from '{principal}'",
        "cli": (
            f"# Detach the managed policy that grants {action}:\n"
            f"aws iam detach-role-policy \\\n"
            f"  --role-name {principal} \\\n"
            f"  --policy-arn <arn-of-policy-granting-{action}>\n\n"
            f"# Or add an inline deny:\n"
            f"aws iam put-role-policy \\\n"
            f"  --role-name {principal} \\\n"
            f"  --policy-name DenyPolicyModification \\\n"
            f"  --policy-document '{policy_doc}'"
        ),
        "terraform": (
            f'resource "aws_iam_role_policy" "deny_policy_mod_{principal}" {{\n'
            f'  name   = "DenyPolicyModification"\n'
            f'  role   = "{principal}"\n'
            f'  policy = jsonencode({{\n'
            f'    Version = "2012-10-17"\n'
            f'    Statement = [{{\n'
            f'      Effect   = "Deny"\n'
            f'      Action   = ["iam:AttachRolePolicy","iam:PutRolePolicy","iam:AttachUserPolicy","iam:PutUserPolicy"]\n'
            f'      Resource = "*"\n'
            f'    }}]\n'
            f'  }})\n'
            f'}}'
        ),
    }


def _fix_access_key(src: str) -> Dict[str, str]:
    principal = _principal_name(src)
    return {
        "description": f"Remove iam:CreateAccessKey permission from '{principal}'",
        "cli": (
            f"# Detach the managed policy granting iam:CreateAccessKey:\n"
            f"aws iam detach-role-policy \\\n"
            f"  --role-name {principal} \\\n"
            f"  --policy-arn <arn-of-offending-policy>\n\n"
            f"# Or list current access keys and rotate/delete:\n"
            f"aws iam list-access-keys --user-name <target-user>\n"
            f"aws iam delete-access-key \\\n"
            f"  --user-name <target-user> --access-key-id <key-id>"
        ),
        "terraform": (
            f'# Remove iam:CreateAccessKey from the IAM policy\n'
            f'# attached to role/user "{principal}".'
        ),
    }


def _fix_login_profile(src: str) -> Dict[str, str]:
    principal = _principal_name(src)
    return {
        "description": f"Remove iam:CreateLoginProfile / iam:UpdateLoginProfile from '{principal}'",
        "cli": (
            f"aws iam detach-role-policy \\\n"
            f"  --role-name {principal} \\\n"
            f"  --policy-arn <arn-of-offending-policy>"
        ),
        "terraform": (
            f'# Remove iam:CreateLoginProfile and iam:UpdateLoginProfile\n'
            f'# from the IAM policy attached to "{principal}".'
        ),
    }


def _fix_create_user(src: str) -> Dict[str, str]:
    principal = _principal_name(src)
    return {
        "description": f"Remove iam:CreateUser permission from '{principal}'",
        "cli": (
            f"aws iam detach-role-policy \\\n"
            f"  --role-name {principal} \\\n"
            f"  --policy-arn <arn-of-offending-policy>"
        ),
        "terraform": (
            f'# Remove iam:CreateUser from the IAM policy attached to "{principal}".'
        ),
    }


def _fix_full_admin(src: str) -> Dict[str, str]:
    principal = _principal_name(src)
    return {
        "description": f"Detach AdministratorAccess from '{principal}' and apply least-privilege policy",
        "cli": (
            f"aws iam detach-role-policy \\\n"
            f"  --role-name {principal} \\\n"
            f"  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        ),
        "terraform": (
            f'# Remove the AdministratorAccess attachment from "{principal}":\n'
            f'# Delete or comment out:\n'
            f'# resource "aws_iam_role_policy_attachment" "admin_attach" {{\n'
            f'#   role       = "{principal}"\n'
            f'#   policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"\n'
            f'# }}'
        ),
    }


def _fix_privilege_propagation(src: str) -> Dict[str, str]:
    principal = _principal_name(src)
    return {
        "description": f"Remove wildcard IAM permission (iam:* or *) from '{principal}'",
        "cli": (
            f"# List and detach managed policies:\n"
            f"aws iam list-attached-role-policies --role-name {principal}\n"
            f"aws iam detach-role-policy \\\n"
            f"  --role-name {principal} \\\n"
            f"  --policy-arn <arn-of-wildcard-policy>"
        ),
        "terraform": (
            f'# Replace the wildcard Action ("iam:*" or "*") in the policy\n'
            f'# attached to "{principal}" with explicit action list.'
        ),
    }


def _fix_generic(src: str, dst: str) -> Dict[str, str]:
    return {
        "description": f"Remove or restrict the IAM permission edge: '{_strip(src)}' → '{_strip(dst)}'",
        "cli": (
            f"# Review and restrict the policy granting access from {_strip(src)} to {_strip(dst)}.\n"
            f"aws iam list-attached-role-policies --role-name {_strip(src)}"
        ),
        "terraform": (
            f'# Audit and restrict the IAM policy allowing "{_strip(src)}" to reach "{_strip(dst)}".'
        ),
    }


# ── Public API ────────────────────────────────────────────────────────────────

def edge_to_cli_fix(src: str, dst: str) -> Dict[str, Any]:
    """
    Map a single remediation edge (src, dst) to an actionable fix dict.

    Returns:
        {
          "edge":        [src, dst],
          "description": str,
          "cli":         str,
          "terraform":   str,
        }
    """
    s, d = src.lower(), dst.lower()

    if "passrole" in s or "passrole" in d:
        fix = _fix_passrole(src)
    elif "full_admin" in d or "administratoraccess" in d:
        fix = _fix_full_admin(src)
    elif "privilege_propagation" in d:
        fix = _fix_privilege_propagation(src)
    elif "attachrolepolicy" in d or "putrolepolicy" in d or \
         "attachuserpolicy" in d or "putuserpolicy" in d:
        action = dst.replace("ACTION::", "").split("::")[0]
        fix = _fix_policy_modification(src, action)
    elif "createaccesskey" in d:
        fix = _fix_access_key(src)
    elif "createloginprofile" in d or "updateloginprofile" in d:
        fix = _fix_login_profile(src)
    elif "createuser" in d:
        fix = _fix_create_user(src)
    elif "assumerole" in d or (not dst.startswith("ACTION::") and not dst.startswith("CAPABILITY::")):
        fix = _fix_assumerole(src, dst)
    else:
        fix = _fix_generic(src, dst)

    return {"edge": [src, dst], **fix}


def generate_cli_fixes(recommended_fixes: List) -> List[Dict[str, Any]]:
    """
    Convert a list of fix edges from compute_weighted_minimal_cut() into
    a list of actionable fix dicts with AWS CLI and Terraform snippets.

    Args:
        recommended_fixes: list of (src, dst) tuples or [src, dst] lists

    Returns:
        Ordered list of fix dicts, one per edge.
    """
    results = []
    for fix in recommended_fixes:
        if isinstance(fix, (list, tuple)) and len(fix) == 2:
            src, dst = str(fix[0]), str(fix[1])
        elif isinstance(fix, str) and " -> " in fix:
            src, dst = fix.split(" -> ", 1)
        else:
            src, dst = str(fix), ""
        results.append(edge_to_cli_fix(src, dst))
    return results
