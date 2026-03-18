import logging
import boto3

log = logging.getLogger(__name__)


def fetch_account_authorization(profile=None):
    """
    Fetch complete IAM data from AWS, including managed policy documents.

    Steps:
      1. Paginate get_account_authorization_details — gets users, roles,
         groups, and *customer-managed* policy documents in one call.
      2. Collect every managed policy ARN attached to any user/role.
      3. For ARNs not already in the Policies list (i.e. AWS-managed policies
         like AdministratorAccess, PowerUserAccess, ReadOnlyAccess), call
         get_policy + get_policy_version to fetch the actual document.

    Returns a dict in the same format as get_account_authorization_details
    with a fully populated Policies list.
    """

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    iam     = session.client("iam")

    full_data = {
        "UserDetailList":  [],
        "RoleDetailList":  [],
        "GroupDetailList": [],
        "Policies":        [],
    }

    # ── Step 1: paginate base IAM data ────────────────────────────────────────
    paginator = iam.get_paginator("get_account_authorization_details")
    for page in paginator.paginate():
        full_data["UserDetailList"].extend(page.get("UserDetailList",  []))
        full_data["RoleDetailList"].extend(page.get("RoleDetailList",  []))
        full_data["GroupDetailList"].extend(page.get("GroupDetailList", []))
        full_data["Policies"].extend(page.get("Policies", []))

    log.info(
        "Fetched %d users, %d roles, %d customer-managed policies",
        len(full_data["UserDetailList"]),
        len(full_data["RoleDetailList"]),
        len(full_data["Policies"]),
    )

    # ── Step 2: collect all attached managed policy ARNs ─────────────────────
    attached_arns: set = set()
    for principal in full_data["UserDetailList"] + full_data["RoleDetailList"]:
        for p in principal.get("AttachedManagedPolicies", []) or []:
            arn = p.get("PolicyArn")
            if arn:
                attached_arns.add(arn)

    # ── Step 3: fetch documents for AWS-managed policies not in Policies list ─
    known_arns = {p["Arn"] for p in full_data["Policies"] if "Arn" in p}
    missing    = attached_arns - known_arns

    log.info(
        "%d unique managed policy ARNs attached; %d need document fetch",
        len(attached_arns), len(missing),
    )

    for arn in missing:
        try:
            policy     = iam.get_policy(PolicyArn=arn)["Policy"]
            version_id = policy["DefaultVersionId"]
            version    = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
            doc        = version["PolicyVersion"]["Document"]

            full_data["Policies"].append({
                "Arn":        arn,
                "PolicyName": policy.get("PolicyName", arn),
                "PolicyVersionList": [{
                    "Document":         doc,
                    "IsDefaultVersion": True,
                    "VersionId":        version_id,
                }],
            })
            log.debug("Resolved managed policy document: %s", arn)

        except Exception as exc:
            log.warning("Could not fetch policy document for %s: %s", arn, exc)

    log.info("Total policies in export: %d", len(full_data["Policies"]))
    return full_data
