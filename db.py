"""
db.py
SQLite persistence layer for IAM Defender.

Stores scan history so results survive server restarts and can be
retrieved by scan ID without relying on Flask session alone.

Tables:
    scans          — one row per uploaded file analysis
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
    log.debug("Database initialised at %s", DB_PATH)


def save_scan(
    filename: str,
    findings: List[Dict],
    criticality: Dict[str, float],
    remediation: Dict[str, Any],
    total_principals: int,
    graph: Optional[Dict] = None,
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
                 critical, high, medium, low, criticality_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (now, filename, total_principals, len(findings),
             critical, high, medium, low, criticality_json),
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
        return []


def remove_suppression(suppression_id: int) -> None:
    """Delete a suppression by its id."""
    with _connect() as conn:
        conn.execute("DELETE FROM suppressions WHERE id = ?", (suppression_id,))
    log.info("Removed suppression id=%d", suppression_id)
