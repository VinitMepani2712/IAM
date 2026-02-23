from core.privilege_model import CAPABILITY_WEIGHTS


def compute_risk(capability_class, path_length, centrality_score, cross_account=False):

    # Base risk per capability
    base_scores = {
        "FULL_ADMIN": 95,
        "COMPUTE_LAUNCH": 85,
        "ROLE_ASSUMPTION": 60
    }

    base = base_scores.get(capability_class, 50)

    # Shorter path = more dangerous
    path_factor = max(0, 20 - (path_length * 3))

    # Central nodes amplify blast radius
    centrality_factor = min(centrality_score * 15, 20)

    # Cross-account pivot is very dangerous
    cross_bonus = 20 if cross_account else 0

    score = base + path_factor + centrality_factor + cross_bonus

    return min(score, 100)


def classify_severity(score):

    if score >= 75:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    else:
        return "LOW"
