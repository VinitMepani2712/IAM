"""
analysis/escalation.py
Unified escalation result type and convenience re-exports.

Provides:
  - EscalationResult dataclass — a typed wrapper around the finding dict
    used throughout the codebase, with helper methods for conversion.
  - Re-exports of the primary escalation analysis functions so callers
    can import everything from one place.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class EscalationResult:
    """
    Structured, typed representation of a single escalation path finding.

    Mirrors the dict schema produced by engine/analyzer.py and main.py so
    that either format can be converted via .to_dict() / .from_dict().
    """

    principal:       str
    account_id:      str
    capability:      str
    risk:            float
    severity:        str            # CRITICAL | HIGH | MEDIUM | LOW
    cross_account:   bool
    path:            List[str]
    pattern:         str            # e.g. "POLICY_MANIPULATION"
    mitre:           str            # e.g. "T1098 - Account Manipulation"
    all_patterns:    List[Dict[str, str]] = field(default_factory=list)
    condition_flags: Dict[str, Any]      = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def path_length(self) -> int:
        return len(self.path)

    @property
    def is_critical(self) -> bool:
        return self.severity == "CRITICAL"

    @property
    def mfa_required(self) -> bool:
        return self.condition_flags.get("requires_mfa", False)

    @property
    def external_id_required(self) -> bool:
        return self.condition_flags.get("requires_external_id", False)

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Convert to the plain dict format used by the web app and PDF generator."""
        return {
            "principal":       self.principal,
            "account_id":      self.account_id,
            "capability":      self.capability,
            "risk":            self.risk,
            "severity":        self.severity,
            "cross_account":   self.cross_account,
            "path":            self.path,
            "pattern":         self.pattern,
            "mitre":           self.mitre,
            "all_patterns":    self.all_patterns,
            "condition_flags": self.condition_flags,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EscalationResult":
        """Construct an EscalationResult from a plain finding dict."""
        return cls(
            principal=d.get("principal", ""),
            account_id=d.get("account_id", ""),
            capability=d.get("capability", ""),
            risk=float(d.get("risk", 0.0)),
            severity=d.get("severity", "LOW"),
            cross_account=bool(d.get("cross_account", False)),
            path=list(d.get("path", [])),
            pattern=d.get("pattern", "GENERIC_ESCALATION"),
            mitre=d.get("mitre", ""),
            all_patterns=list(d.get("all_patterns", [])),
            condition_flags=dict(d.get("condition_flags", {})),
        )


# ── Re-exports from the analysis stack ────────────────────────────────────────
# Import from here instead of hunting across modules.

from analysis.risk_model import compute_risk, classify_severity          # noqa: F401, E402
from analysis.attack_patterns import classify_attack_pattern             # noqa: F401, E402
from analysis.centrality import compute_escalation_centrality            # noqa: F401, E402
from analysis.dominator import compute_dominators                        # noqa: F401, E402
from analysis.min_cut import compute_weighted_minimal_cut                # noqa: F401, E402
from analysis.criticality import compute_node_criticality                # noqa: F401, E402
