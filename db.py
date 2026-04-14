"""
db.py
SQLite persistence layer for IAM Defender.

Stores scan history so results survive server restarts and can be
retrieved by scan ID without relying on Flask session alone.

Tables:
    users          — registered user accounts
    scans          — one row per uploaded file analysis (linked to user)
    scan_findings  — serialised findings list per scan
    scan_remediation — serialised remediation dict per scan
"""

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

DB_PATH = os.environ.get("IAM_DB_PATH", "iam_defender.db")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they don't exist. Call once at app startup."""
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS finding_notes (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                principal   TEXT NOT NULL,
                capability  TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'open',
                note        TEXT NOT NULL DEFAULT '',
                updated_at  TEXT NOT NULL,
                UNIQUE(principal, capability)
            );

            CREATE TABLE IF NOT EXISTS scans (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at       TEXT    NOT NULL,
                filename         TEXT    NOT NULL,
                total_principals INTEGER NOT NULL DEFAULT 0,
                total_findings   INTEGER NOT NULL DEFAULT 0,
                critical         INTEGER NOT NULL DEFAULT 0,
                high             INTEGER NOT NULL DEFAULT 0,
                medium           INTEGER NOT NULL DEFAULT 0,
                low              INTEGER NOT NULL DEFAULT 0,
                criticality_json TEXT    NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS scan_findings (
                scan_id  INTEGER PRIMARY KEY,
                data     TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS scan_remediation (
                scan_id  INTEGER PRIMARY KEY,
                data     TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS scan_graph (
                scan_id  INTEGER PRIMARY KEY,
                data     TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS suppressions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                principal  TEXT NOT NULL,
                capability TEXT NOT NULL,
                reason     TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                UNIQUE(principal, capability)
            );
        """)
    # Migration: add user_id to scans if upgrading from older schema
    try:
        conn.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id)")
        log.info("Migrated scans table: added user_id column")
    except Exception:
        pass  # column already exists

    log.debug("Database initialised at %s", DB_PATH)


# ── User account helpers ──────────────────────────────────────────────────────

def create_user(username: str, password_hash: str) -> Optional[int]:
    """Insert a new user. Returns the new user id, or None if username is taken."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        with _connect() as conn:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, now),
            )
        return cur.lastrowid
    except Exception:
        return None  # username already taken (UNIQUE constraint)


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Return the user row for username, or None if not found."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    return dict(row) if row else None


def get_scan_user_id(scan_id: int) -> Optional[int]:
    """Return the user_id that owns this scan, or None."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT user_id FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    return row["user_id"] if row else None


def list_scans_for_user(user_id: int) -> List[Dict[str, Any]]:
    """Return summary list of scans owned by user_id, newest first."""
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, created_at, filename, total_principals,
                   total_findings, critical, high, medium, low
            FROM   scans
            WHERE  user_id = ?
            ORDER  BY id DESC
            """,
            (user_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def delete_all_scans_for_user(user_id: int) -> int:
    """Delete all scans owned by user_id. Returns count removed."""
    with _connect() as conn:
        scan_ids = [r[0] for r in conn.execute(
            "SELECT id FROM scans WHERE user_id = ?", (user_id,)
        ).fetchall()]
        for sid in scan_ids:
            conn.execute("DELETE FROM scan_findings    WHERE scan_id = ?", (sid,))
            conn.execute("DELETE FROM scan_remediation WHERE scan_id = ?", (sid,))
            conn.execute("DELETE FROM scan_graph       WHERE scan_id = ?", (sid,))
        conn.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
    log.info("Deleted %d scans for user_id=%d", len(scan_ids), user_id)
    return len(scan_ids)


def save_scan(
    filename: str,
    findings: List[Dict],
    criticality: Dict[str, float],
    remediation: Dict[str, Any],
    total_principals: int,
    graph: Optional[Dict] = None,
    user_id: Optional[int] = None,
) -> int:
    """
    Persist a completed scan and return its new scan_id.

    Args:
        filename:         Original uploaded filename.
        findings:         List of finding dicts from analyze_environment_data().
        criticality:      Node criticality scores dict.
        remediation:      Remediation summary dict.
        total_principals: Number of principals analysed.

    Returns:
        Integer scan_id for this record.
    """
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high     = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium   = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low      = sum(1 for f in findings if f.get("severity") == "LOW")

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # Serialise — convert any non-JSON-native types
    def _serialise(obj):
        if isinstance(obj, (set, tuple)):
            return list(obj)
        return str(obj)

    findings_json    = json.dumps(findings,    default=_serialise)
    remediation_json = json.dumps(remediation, default=_serialise)
    criticality_json = json.dumps({k: float(v) for k, v in criticality.items()})

    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO scans
                (created_at, filename, total_principals, total_findings,
                 critical, high, medium, low, criticality_json, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (now, filename, total_principals, len(findings),
             critical, high, medium, low, criticality_json, user_id),
        )
        scan_id = cur.lastrowid

        conn.execute(
            "INSERT INTO scan_findings  (scan_id, data) VALUES (?, ?)",
            (scan_id, findings_json),
        )
        conn.execute(
            "INSERT INTO scan_remediation (scan_id, data) VALUES (?, ?)",
            (scan_id, remediation_json),
        )

        if graph is not None:
            graph_json = json.dumps(graph, default=_serialise)
            conn.execute(
                "INSERT INTO scan_graph (scan_id, data) VALUES (?, ?)",
                (scan_id, graph_json),
            )

    log.info("Scan #%d saved — %d findings (%d critical)", scan_id, len(findings), critical)
    return scan_id


def get_scan(scan_id: int) -> Optional[Dict[str, Any]]:
    """
    Load a complete scan record by ID.

    Returns:
        Dict with keys: id, created_at, filename, total_principals,
        total_findings, critical, high, medium, low,
        findings, criticality, remediation
        Or None if the scan_id doesn't exist.
    """
    with _connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None

        findings_row    = conn.execute(
            "SELECT data FROM scan_findings    WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        remediation_row = conn.execute(
            "SELECT data FROM scan_remediation WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        graph_row = conn.execute(
            "SELECT data FROM scan_graph WHERE scan_id = ?", (scan_id,)
        ).fetchone()

    _empty_graph = {"nodes": [], "edges": [], "full_nodes": [], "full_edges": []}
    return {
        "id":               row["id"],
        "created_at":       row["created_at"],
        "filename":         row["filename"],
        "total_principals": row["total_principals"],
        "total_findings":   row["total_findings"],
        "critical":         row["critical"],
        "high":             row["high"],
        "medium":           row["medium"],
        "low":              row["low"],
        "criticality":      json.loads(row["criticality_json"]),
        "findings":         json.loads(findings_row["data"])    if findings_row    else [],
        "remediation":      json.loads(remediation_row["data"]) if remediation_row else {},
        "graph":            json.loads(graph_row["data"])        if graph_row        else _empty_graph,
    }


def list_scans() -> List[Dict[str, Any]]:
    """
    Return a summary list of all past scans, newest first.

    Each entry: id, created_at, filename, total_principals, total_findings,
                critical, high, medium, low
    """
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, created_at, filename, total_principals,
                   total_findings, critical, high, medium, low
            FROM   scans
            ORDER  BY id DESC
            """
        ).fetchall()

    return [dict(row) for row in rows]


# ── Suppression helpers ───────────────────────────────────────────────────────

def add_suppression(principal: str, capability: str, reason: str = "") -> None:
    """Mark a (principal, capability) pair as a false positive. Idempotent."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _connect() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO suppressions (principal, capability, reason, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (principal, capability, reason, now),
        )
    log.info("Suppressed finding: %s → %s", principal, capability)


def list_suppressions() -> List[Dict[str, Any]]:
    """Return all suppressions, newest first."""
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT * FROM suppressions ORDER BY id DESC"
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        log.warning("list_suppressions failed", exc_info=True)
        return []


def remove_suppression(suppression_id: int) -> None:
    """Delete a suppression by its id."""
    with _connect() as conn:
        conn.execute("DELETE FROM suppressions WHERE id = ?", (suppression_id,))
    log.info("Removed suppression id=%d", suppression_id)


# ── Scan comparison & trend helpers ──────────────────────────────────────────

def compare_scans(id_a: int, id_b: int) -> Optional[Dict[str, Any]]:
    """
    Compare two scans. scan_a is the baseline, scan_b is the newer scan.

    Returns a dict with:
        scan_a / scan_b  — metadata for each scan
        new_findings     — findings in B not present in A  (regressions)
        fixed_findings   — findings in A not present in B  (improvements)
        worsened         — findings in both where risk increased in B
        improved         — findings in both where risk decreased in B
        persisted        — count of findings present in both scans unchanged
        delta            — severity count deltas (positive = worse)
    """
    scan_a = get_scan(id_a)
    scan_b = get_scan(id_b)
    if not scan_a or not scan_b:
        return None

    def _key(f):
        return (f["principal"], f["capability"], f.get("pattern", ""))

    map_a = {_key(f): f for f in scan_a["findings"]}
    map_b = {_key(f): f for f in scan_b["findings"]}

    new_findings   = [map_b[k] for k in map_b if k not in map_a]
    fixed_findings = [map_a[k] for k in map_a if k not in map_b]

    worsened  = []
    improved  = []
    persisted = 0
    for k in map_b:
        if k in map_a:
            persisted += 1
            risk_a = map_a[k].get("risk", 0)
            risk_b = map_b[k].get("risk", 0)
            if risk_b > risk_a:
                entry = dict(map_b[k])
                entry["risk_delta"] = round(risk_b - risk_a, 1)
                worsened.append(entry)
            elif risk_b < risk_a:
                entry = dict(map_b[k])
                entry["risk_delta"] = round(risk_b - risk_a, 1)
                improved.append(entry)

    _meta_keys = ["id", "created_at", "filename", "total_findings",
                  "critical", "high", "medium", "low", "total_principals"]

    return {
        "scan_a":        {k: scan_a[k] for k in _meta_keys},
        "scan_b":        {k: scan_b[k] for k in _meta_keys},
        "new_findings":  sorted(new_findings,   key=lambda f: f.get("risk", 0), reverse=True),
        "fixed_findings": sorted(fixed_findings, key=lambda f: f.get("risk", 0), reverse=True),
        "worsened":      sorted(worsened, key=lambda f: f.get("risk_delta", 0), reverse=True),
        "improved":      sorted(improved, key=lambda f: f.get("risk_delta", 0)),
        "persisted":     persisted,
        "delta": {
            "total":    len(scan_b["findings"]) - len(scan_a["findings"]),
            "critical": scan_b["critical"] - scan_a["critical"],
            "high":     scan_b["high"]     - scan_a["high"],
            "medium":   scan_b["medium"]   - scan_a["medium"],
            "low":      scan_b["low"]      - scan_a["low"],
        },
    }


def delete_scan(scan_id: int) -> None:
    """Delete a scan and all its associated data by ID."""
    with _connect() as conn:
        conn.execute("DELETE FROM scan_findings    WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scan_remediation WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scan_graph       WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scans            WHERE id      = ?", (scan_id,))
    log.info("Deleted scan #%d", scan_id)


def rename_scan(scan_id: int, new_name: str) -> bool:
    """Rename the filename label of a scan. Returns True if a row was updated."""
    with _connect() as conn:
        cur = conn.execute(
            "UPDATE scans SET filename = ? WHERE id = ?",
            (new_name.strip(), scan_id),
        )
    log.info("Renamed scan #%d → %s", scan_id, new_name.strip())
    return cur.rowcount > 0


def delete_all_scans() -> int:
    """Delete every scan and return how many were removed."""
    with _connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        conn.executescript("""
            DELETE FROM scan_findings;
            DELETE FROM scan_remediation;
            DELETE FROM scan_graph;
            DELETE FROM scans;
        """)
    log.info("Deleted all %d scans", count)
    return count


def upsert_finding_note(principal: str, capability: str, status: str, note: str = "") -> None:
    """Create or update the status/note for a (principal, capability) finding."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO finding_notes (principal, capability, status, note, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(principal, capability) DO UPDATE SET
                status = excluded.status,
                note   = excluded.note,
                updated_at = excluded.updated_at
            """,
            (principal, capability, status, note, now),
        )


def get_finding_notes() -> Dict[str, Dict]:
    """Return all notes keyed by 'principal::capability' for fast dashboard lookup."""
    try:
        with _connect() as conn:
            rows = conn.execute("SELECT * FROM finding_notes").fetchall()
        return {f"{r['principal']}::{r['capability']}": dict(r) for r in rows}
    except Exception:
        return {}


def delete_finding_note(principal: str, capability: str) -> None:
    """Remove a status/note (resets finding to open)."""
    with _connect() as conn:
        conn.execute(
            "DELETE FROM finding_notes WHERE principal = ? AND capability = ?",
            (principal, capability),
        )


def get_trend_data(user_id: Optional[int] = None, limit: int = 20) -> List[Dict[str, Any]]:
    """
    Return per-scan severity counts ordered oldest→newest for trend charts.
    Scoped to user_id when provided. Limited to the most recent `limit` scans.
    """
    with _connect() as conn:
        if user_id is not None:
            rows = conn.execute(
                """
                SELECT id, created_at, filename, total_findings,
                       critical, high, medium, low
                FROM   scans
                WHERE  user_id = ?
                ORDER  BY id DESC
                LIMIT  ?
                """,
                (user_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, created_at, filename, total_findings,
                       critical, high, medium, low
                FROM   scans
                ORDER  BY id DESC
                LIMIT  ?
                """,
                (limit,),
            ).fetchall()
    # Return oldest-first so chart renders left-to-right
    return list(reversed([dict(r) for r in rows]))
