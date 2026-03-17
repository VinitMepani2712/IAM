from core.privilege_model import CAPABILITY_WEIGHTS


def compute_risk(
    capability_class: str,
    path_length: int,
    centrality_score: float,
    cross_account: bool = False,
    requires_mfa: bool = False,
    requires_external_id: bool = False,
    source_ip_restricted: bool = False,
    org_id_required: bool = False,
    region_restricted: bool = False,
) -> float:
    """
    Compute a 0–100 risk score for an escalation path.

    Design goals — produce a realistic severity spread:
      CRITICAL  (≥ 80): Full admin, cross-account, short direct chains
      HIGH      (≥ 55): Compute/policy abuse, moderate chains
      MEDIUM    (≥ 30): Access key / console, longer chains
      LOW       (<  30): Long multi-hop paths to low-impact capabilities

    Key levers:
      base          — capability impact ceiling (40–70 range)
      directness    — large bonus for short paths, fades quickly with hops
      centrality    — how many paths run through this node
      cross_account — major amplifier
      conditions    — MFA / ExternalId reduce risk (not eliminated, just harder)
    """

    # ── 1. Capability base score ─────────────────────────────────────────────
    # Deliberately moderate so that path length and context determine final tier.
    base_scores = {
        "FULL_ADMIN":             70,   # reaches CRITICAL only with short/cross path
        "COMPUTE_LAUNCH":         60,   # HIGH by default, CRITICAL when direct
        "POLICY_MODIFICATION":    55,
        "PRIVILEGE_PROPAGATION":  50,
        "CONSOLE_ACCESS":         38,   # MEDIUM by default, HIGH only when short chain
        "ACCESS_KEY_PERSISTENCE": 32,   # MEDIUM by default
        "ROLE_ASSUMPTION":        20,   # LOW by default — informational risk
        "IDENTITY_CREATION":      30,
        # Low-impact read/recon capabilities
        "DATA_READ":              15,
        "LOG_ACCESS":             12,
        "AUDIT_READ":             18,
        "RECON":                  10,
    }
    base = base_scores.get(capability_class, 25)

    # ── 2. Path directness bonus ─────────────────────────────────────────────
    # path_length includes principal + action/role nodes + capability
    # A direct 2-node path (principal → capability) gives +20
    # Each extra hop halves the bonus (exponential decay):
    #   len 2  → +20    (direct)
    #   len 3  → +14
    #   len 4  → +10
    #   len 5  → +7
    #   len 6+ → +5 or less
    extra_hops = max(0, path_length - 2)
    directness = round(20 * (0.7 ** extra_hops))

    # ── 3. Centrality amplifier ──────────────────────────────────────────────
    # A node appearing in many escalation paths has higher blast radius.
    # Capped at +8 — should not single-handedly push a LOW into HIGH.
    centrality_factor = round(min(centrality_score * 8, 8))

    # ── 4. Cross-account amplifier ───────────────────────────────────────────
    # Crossing account boundaries dramatically increases blast radius and
    # bypasses account-level SCPs / detection.
    cross_bonus = 18 if cross_account else 0

    # ── 5. Raw score ─────────────────────────────────────────────────────────
    raw = base + directness + centrality_factor + cross_bonus
    capped = min(raw, 100)

    # ── 6. Condition mitigations ─────────────────────────────────────────────
    # Applied AFTER cap so mitigations always visibly reduce the displayed score.
    # MFA and ExternalId are strong controls; IP/Org/Region are network-layer
    # restrictions that reduce exploitability from external actors.
    mfa_reduction    = -15 if requires_mfa else 0
    ext_id_reduction = -10 if requires_external_id else 0
    ip_reduction     =  -8 if source_ip_restricted else 0
    org_reduction    =  -5 if org_id_required else 0
    region_reduction =  -5 if region_restricted else 0
    score = capped + mfa_reduction + ext_id_reduction + ip_reduction + org_reduction + region_reduction

    return round(max(0.0, min(float(score), 100.0)), 1)


def classify_severity(score: float) -> str:
    """
    Thresholds tuned to match expected enterprise distribution:
      CRITICAL ≥ 80  →  5–10  findings  (direct admin / cross-account)
      HIGH     ≥ 55  →  15–30 findings  (compute/policy, moderate chains)
      MEDIUM   ≥ 30  →  20–40 findings  (access-key/console, longer chains)
      LOW      <  30 →  30+   findings  (long hops to low-impact caps)
    """
    if score >= 80:
        return "CRITICAL"
    elif score >= 55:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"