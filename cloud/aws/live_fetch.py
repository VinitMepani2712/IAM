import boto3
import json

def fetch_account_authorization(profile=None):

    if profile:
        session = boto3.Session(profile_name=profile)
    else:
        session = boto3.Session()

    iam = session.client("iam")

    paginator = iam.get_paginator("get_account_authorization_details")

    full_data = {
        "UserDetailList": [],
        "RoleDetailList": []
    }

    for page in paginator.paginate():
        full_data["UserDetailList"].extend(page.get("UserDetailList", []))
        full_data["RoleDetailList"].extend(page.get("RoleDetailList", []))

    return full_data
