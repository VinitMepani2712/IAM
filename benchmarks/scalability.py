import time
import matplotlib.pyplot as plt
from core.entities import Principal, PolicyStatement
from graph.attack_graph import build_attack_graph
from graph.reachability import find_minimal_escalation_path


def _allow(actions: set) -> list:
    return [PolicyStatement(effect="Allow", actions=actions, resources={"*"})]


def generate_chain_environment(size):
    """
    Generate a linear role chain:
    UserA → Role1 → Role2 → ... → RoleN → Admin
    """
    principals = {}

    principals["UserA"] = Principal(
        name="UserA",
        account_id="BenchmarkAccount",
        type="user",
        policy_statements=_allow({"sts:AssumeRole"}),
        trusts=set()
    )

    previous = "UserA"

    for i in range(1, size + 1):
        role_name = f"Role{i}"
        actions   = {"sts:AssumeRole"} if i < size else {"*"}

        principals[role_name] = Principal(
            name=role_name,
            account_id="BenchmarkAccount",
            type="role",
            policy_statements=_allow(actions),
            trusts={previous}
        )

        previous = role_name

    return principals


def run_scalability_test(max_size=2000, step=200):

    sizes    = []
    runtimes = []

    for size in range(step, max_size + 1, step):

        principals = generate_chain_environment(size)

        start = time.time()
        graph = build_attack_graph(principals)
        find_minimal_escalation_path(graph, "UserA")
        end   = time.time()

        elapsed = round(end - start, 4)
        sizes.append(size)
        runtimes.append(elapsed)

        print(f"Roles: {size:>5} | Time: {elapsed:.4f} sec")

    plt.figure(figsize=(8, 5))
    plt.plot(sizes, runtimes, marker="o")
    plt.xlabel("Number of Roles")
    plt.ylabel("Execution Time (seconds)")
    plt.title("IAM Attack Graph Scalability")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("scalability_results.png", dpi=150)
    plt.show()

    return list(zip(sizes, runtimes))


if __name__ == "__main__":
    run_scalability_test()
