import time
import matplotlib.pyplot as plt
from models.entities import Principal
from graph.attack_graph import build_attack_graph
from graph.reachability import find_minimal_escalation_path


def generate_chain_environment(size):
    """
    Generate a linear role chain:
    UserA → Role1 → Role2 → ... → RoleN → Admin
    """
    principals = {}

    user = Principal(
        name="UserA",
        type="user",
        allow_actions={"sts:AssumeRole"},
        deny_actions=set(),
        trusts=set()
    )
    principals["UserA"] = user

    previous = "UserA"

    for i in range(1, size + 1):
        role_name = f"Role{i}"

        allow = {"sts:AssumeRole"} if i < size else {"AdministratorAccess"}

        role = Principal(
            name=role_name,
            type="role",
            allow_actions=allow,
            deny_actions=set(),
            trusts={previous}
        )

        principals[role_name] = role
        previous = role_name

    return principals


def run_scalability_test(max_size=2000, step=200):

    sizes = []
    runtimes = []

    for size in range(step, max_size + 1, step):

        principals = generate_chain_environment(size)

        start = time.time()

        graph = build_attack_graph(principals)
        find_minimal_escalation_path(graph, "UserA")

        end = time.time()

        sizes.append(size)
        runtimes.append(end - start)

        print(f"Roles: {size} | Time: {round(end - start, 4)} sec")

    plt.figure(figsize=(8, 5))
    plt.plot(sizes, runtimes, marker='o')
    plt.xlabel("Number of Roles")
    plt.ylabel("Execution Time (seconds)")
    plt.title("IAM Attack Graph Scalability")
    plt.grid(True)
    plt.show()
