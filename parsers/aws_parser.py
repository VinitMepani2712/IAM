import json
import os
from models.entities import Principal


def parse_aws_iam_json(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, "r") as f:
        data = json.load(f)

    principals = {}

    # Parse Users
    for user in data.get("UserDetailList", []):
        name = user["UserName"]

        allow = set()
        deny = set()
        trusts = set()

        for policy in user.get("UserPolicyList", []):
            for stmt in policy["PolicyDocument"].get("Statement", []):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                if stmt.get("Effect") == "Allow":
                    allow.update(actions)
                elif stmt.get("Effect") == "Deny":
                    deny.update(actions)

        principals[name] = Principal(
            name=name,
            type="user",
            allow_actions=allow,
            deny_actions=deny,
            trusts=trusts
        )

    # Parse Roles
    for role in data.get("RoleDetailList", []):
        name = role["RoleName"]

        allow = set()
        deny = set()
        trusts = set()

        # Trust policy
        assume_doc = role.get("AssumeRolePolicyDocument", {})
        for stmt in assume_doc.get("Statement", []):
            if stmt.get("Effect") == "Allow":
                principal = stmt.get("Principal", {}).get("AWS")
                if principal:
                    trusts.add(principal)

        # Inline policies
        for policy in role.get("RolePolicyList", []):
            for stmt in policy["PolicyDocument"].get("Statement", []):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                if stmt.get("Effect") == "Allow":
                    allow.update(actions)
                elif stmt.get("Effect") == "Deny":
                    deny.update(actions)

        principals[name] = Principal(
            name=name,
            type="role",
            allow_actions=allow,
            deny_actions=deny,
            trusts=trusts
        )

    return principals
