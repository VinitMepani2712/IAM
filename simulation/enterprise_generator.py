import random
from core.entities import Principal, PolicyStatement

ACTIONS = [
    "sts:AssumeRole",
    "iam:PassRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreateAccessKey",
    "ec2:RunInstances"
]


def _allow(actions: set) -> list:
    """Wrap a set of action strings into a single Allow PolicyStatement."""
    return [PolicyStatement(effect="Allow", actions=actions, resources={"*"})]


def generate_enterprise_environment(
    num_accounts=10,
    roles_per_account=200,
    users_per_account=20,
    seed=42
):

    random.seed(seed)

    principals = {}

    for acc in range(num_accounts):

        account_id = f"Account{acc}"

        # Users
        for u in range(users_per_account):
            name = f"{account_id}_User{u}"
            principals[name] = Principal(
                name=name,
                account_id=account_id,
                type="user",
                policy_statements=_allow(set(random.sample(ACTIONS, 1))),
                trusts=set()
            )

        # Roles
        for r in range(roles_per_account):
            name = f"{account_id}_Role{r}"
            principals[name] = Principal(
                name=name,
                account_id=account_id,
                type="role",
                policy_statements=_allow(set(random.sample(ACTIONS, 1))),
                trusts=set()
            )

        # Admin roles
        for a in range(5):
            name = f"{account_id}_AdminRole{a}"
            principals[name] = Principal(
                name=name,
                account_id=account_id,
                type="role",
                policy_statements=_allow({"*"}),
                trusts=set()
            )

    # Random trust relationships (bounded fan-out)
    principal_names = list(principals.keys())

    for name, principal in principals.items():
        if principal.type == "role":
            possible_trusts = random.sample(principal_names, k=min(3, len(principal_names)))
            principal.trusts.update(possible_trusts)

    # Inject escalation chains
    inject_escalation_chains(principals, num_accounts)

    return principals


def inject_escalation_chains(principals, num_accounts):

    for acc in range(num_accounts):

        account_id = f"Account{acc}"

        user  = f"{account_id}_User0"
        role1 = f"{account_id}_Role0"
        role2 = f"{account_id}_Role1"
        admin = f"{account_id}_AdminRole0"

        if user in principals and role1 in principals:
            principals[role1].trusts.add(user)

        if role1 in principals and role2 in principals:
            principals[role2].trusts.add(role1)

        if role2 in principals and admin in principals:
            principals[admin].trusts.add(role2)
