from flask import Flask, render_template, request, Response, session, jsonify, redirect, url_for, abort
import functools
import json
import logging
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from werkzeug.utils import secure_filename

from logging_config import setup_logging
setup_logging()

# Load .env file if present (local development convenience)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed — rely on shell environment

log = logging.getLogger(__name__)

from cloud.aws.parser import parse_aws_iam_json
from engine.analyzer import analyze_environment_data, extract_graph_data
from graph.attack_graph import build_attack_graph
from pdf.pdf_report import generate_pdf_report
import db

# ── C3: Fail-fast on missing secret key ──────────────────────────────────────
_secret_key = os.environ.get("IAM_SECRET_KEY")
if not _secret_key:
    raise RuntimeError(
        "IAM_SECRET_KEY environment variable must be set before running. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )

app = Flask(__name__)
app.secret_key = _secret_key

# ── M2: Session security flags ────────────────────────────────────────────────
app.config["SESSION_COOKIE_HTTPONLY"]  = True
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"   # primary CSRF defense
app.config["SESSION_COOKIE_SECURE"]   = os.environ.get("IAM_HTTPS", "0") == "1"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

# ── H1: File upload size limit (10 MB) ───────────────────────────────────────
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

# ── L3: Accepted top-level keys for IAM JSON uploads ─────────────────────────
_IAM_TOP_LEVEL_KEYS = {
    "UserDetailList", "RoleDetailList", "GroupDetailList",
    "Policies", "Principals",                              # both AWS and demo formats
}

# ── C1: Authentication helpers ────────────────────────────────────────────────
_ADMIN_USER     = os.environ.get("IAM_ADMIN_USER",     "admin")
_ADMIN_PASSWORD = os.environ.get("IAM_ADMIN_PASSWORD", "")

def require_auth(f):
    """Redirect to /login for browser routes; 401 for JSON API routes."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated

# ── C2: CSRF helpers (defense-in-depth on top of SameSite=Strict) ─────────────
def _get_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

def csrf_protect(f):
    """Validate CSRF token on state-changing requests (POST/PATCH/DELETE)."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            token = (
                request.headers.get("X-CSRF-Token")
                or (request.get_json(silent=True) or {}).get("csrf_token")
                or request.form.get("csrf_token")
            )
            if not token or not secrets.compare_digest(token, _get_csrf_token()):
                return jsonify({"error": "CSRF validation failed"}), 403
        return f(*args, **kwargs)
    return decorated

# Expose csrf_token() to all Jinja2 templates
app.jinja_env.globals["csrf_token"] = _get_csrf_token

# ── H4: Input validation helpers ──────────────────────────────────────────────
_IDENT_RE  = re.compile(r'^[\w:/@+=.,\s-]{1,256}$')
_STATUS_OK = {"open", "in_remediation", "accepted_risk", "investigating"}

def _validate_identifier(value: str, field: str):
    if not value or len(value) > 256:
        abort(400, f"{field} must be 1–256 characters")
    if not _IDENT_RE.match(value):
        abort(400, f"{field} contains invalid characters")

def _validate_reason(reason: str) -> str:
    return reason[:500] if reason else ""


# ── C1: Login / logout ───────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect("/")
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if (secrets.compare_digest(username, _ADMIN_USER)
                and _ADMIN_PASSWORD
                and secrets.compare_digest(password, _ADMIN_PASSWORD)):
            session.clear()
            session["authenticated"] = True
            session.permanent = True
            _get_csrf_token()          # seed CSRF token immediately after login
            return redirect(request.args.get("next") or "/")
        error = "Invalid credentials."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/")
@require_auth
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
@require_auth
@csrf_protect
def analyze():

    if "file" not in request.files or request.files["file"].filename == "":
        return render_template("index.html", error="Please upload an IAM JSON file.")

    file = request.files["file"]

    # H1/H6: Sanitize filename; reject non-JSON content types
    raw_name = file.filename or "upload.json"
    filename = secure_filename(raw_name) or "upload.json"
    if file.content_type and "json" not in file.content_type.lower() and not filename.endswith(".json"):
        return render_template("index.html", error="Only JSON files are accepted.")

    # L3: Basic schema guard — reject obviously wrong files early
    try:
        data = json.load(file)
    except json.JSONDecodeError:
        log.warning("User uploaded invalid JSON: %s", filename)
        return render_template("index.html", error="Invalid JSON file. Please check the format and try again.")

    if not isinstance(data, dict) or not any(k in data for k in _IAM_TOP_LEVEL_KEYS):
        return render_template("index.html", error="Unrecognised IAM export format. Expected AWS GetAccountAuthorizationDetails JSON.")

    # H2: Generic error to user; full exception to logs
    try:
        principals, scps, _resource_policies = parse_aws_iam_json(data)
    except Exception:
        log.exception("Failed to parse IAM data from '%s'", filename)
        return render_template("index.html", error="Failed to parse IAM data. Please verify your export format.")

    if not principals:
        return render_template("index.html", error="No IAM principals found in the uploaded file.")

    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Run analysis
    findings, criticality, remediation = analyze_environment_data(principals, scps=scps)

    # Filter out suppressed (false-positive) findings
    try:
        suppressed = {(s["principal"], s["capability"]) for s in db.list_suppressions()}
        findings = [f for f in findings
                    if (f.get("principal", ""), f.get("capability", "")) not in suppressed]
    except Exception:
        log.warning("Could not apply suppressions — showing all findings")

    top_critical     = list(criticality.items())[:5] if criticality else []
    top_critical_ids = [node for node, _ in top_critical[:3]]

    # Build graph data (pass SCPs so deny edges are consistent with analysis)
    graph = build_attack_graph(principals, scps=scps)
    nodes,      edges      = extract_graph_data(graph, findings=findings, escalation_only=True)
    full_nodes, full_edges = extract_graph_data(graph, findings=findings, escalation_only=False)

    # Normalise remediation for JSON serialisation
    remediation_serial = {
        "total_paths":       remediation["total_paths"],
        "recommended_fixes": [list(e) if isinstance(e, tuple) else e
                              for e in remediation["recommended_fixes"]],
        "dominators":        list(remediation["dominators"])
                             if hasattr(remediation["dominators"], "__iter__")
                             else [],
    }

    # Persist to SQLite
    scan_id = None
    try:
        scan_id = db.save_scan(
            filename=filename,
            findings=findings,
            criticality=criticality,
            remediation=remediation_serial,
            total_principals=len(principals),
            graph={
                "nodes":      nodes,
                "edges":      edges,
                "full_nodes": full_nodes,
                "full_edges": full_edges,
            },
        )
        session["scan_id"] = scan_id
    except Exception:
        log.exception("Could not save scan to database")

    # L4: Do not store large finding blobs in the session cookie — only the scan_id.
    # All data is retrieved from the DB via scan_id on subsequent requests.

    finding_notes = db.get_finding_notes()

    return render_template(
        "dashboard.html",
        findings=findings,
        criticality=criticality,
        top_critical=top_critical,
        top_critical_ids=top_critical_ids,
        nodes=nodes,
        edges=edges,
        full_nodes=full_nodes,
        full_edges=full_edges,
        remediation=remediation,
        total_principals=len(principals),
        scan_id=scan_id,
        filename=filename,
        scan_time=scan_time,
        finding_notes=finding_notes,
    )


@app.route("/dashboard")
@require_auth
def dashboard():
    scan_id = session.get("scan_id")
    scan    = db.get_scan(scan_id) if scan_id else None
    if not scan:
        return redirect("/")

    findings    = scan["findings"]
    criticality = scan["criticality"]
    remediation = scan["remediation"]
    total       = scan["total_principals"]

    top_critical     = list(criticality.items())[:5] if criticality else []
    top_critical_ids = [node for node, _ in top_critical[:3]]

    graph_data = scan.get("graph", {"nodes": [], "edges": [], "full_nodes": [], "full_edges": []})

    return render_template(
        "dashboard.html",
        findings=findings,
        criticality=criticality,
        top_critical=top_critical,
        top_critical_ids=top_critical_ids,
        nodes=graph_data["nodes"],
        edges=graph_data["edges"],
        full_nodes=graph_data["full_nodes"],
        full_edges=graph_data["full_edges"],
        remediation=remediation,
        total_principals=total,
        scan_id=scan_id,
        filename=scan.get("filename", ""),
        scan_time=scan.get("created_at", ""),
        finding_notes=db.get_finding_notes(),
    )


@app.route("/history-page")
@require_auth
def history_page():
    return render_template("history.html", scans=db.list_scans())


@app.route("/principal/<path:principal_name>")
@require_auth
def principal_detail(principal_name: str):
    # M1/H7: Only allow access to the scan that belongs to this session
    scan_id = request.args.get("scan_id", type=int) or session.get("scan_id")
    if not scan_id or scan_id != session.get("scan_id"):
        abort(403)
    scan    = db.get_scan(scan_id) if scan_id else None
    if not scan:
        return redirect("/")

    all_findings = scan["findings"]
    criticality  = scan["criticality"]

    # Filter findings for this principal
    findings = [f for f in all_findings if f.get("principal") == principal_name]
    if not findings:
        return redirect("/dashboard")

    # All principals this one can reach through paths
    reachable = set()
    for f in findings:
        for node in f.get("path", []):
            if not node.startswith("CAPABILITY::") and not node.startswith("ACTION::"):
                reachable.add(node)
    reachable.discard(principal_name)

    notes = db.get_finding_notes()
    crit_score = criticality.get(principal_name, 0)

    return render_template(
        "principal.html",
        principal_name=principal_name,
        findings=findings,
        reachable=sorted(reachable),
        crit_score=round(crit_score, 3),
        scan_id=scan_id,
        notes=notes,
        account_id=findings[0].get("account_id", ""),
    )


@app.route("/export/json")
@require_auth
def export_json():
    scan_id = request.args.get("scan_id", type=int) or session.get("scan_id")
    # M1: Only serve scans owned by the current session
    if not scan_id or scan_id != session.get("scan_id"):
        abort(403)
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)

    findings    = scan["findings"]
    criticality = scan["criticality"]
    remediation = scan["remediation"]
    total       = scan["total_principals"]

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool":         "IAM Defender — Privilege Escalation Detection Engine",
        "scan_id":      scan_id,
        "summary": {
            "total_principals": total,
            "total_findings":   len(findings),
            "critical":     sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high":         sum(1 for f in findings if f.get("severity") == "HIGH"),
            "medium":       sum(1 for f in findings if f.get("severity") == "MEDIUM"),
            "low":          sum(1 for f in findings if f.get("severity") == "LOW"),
            "cross_account": sum(1 for f in findings if f.get("cross_account")),
        },
        "top_critical_nodes": list(criticality.items())[:10],
        "remediation":        remediation,
        "findings":           findings,
    }

    payload = json.dumps(report, indent=2, default=str)
    return Response(
        payload,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=iam_findings.json"},
    )


@app.route("/export/pdf")
@require_auth
def export_pdf():
    scan_id = request.args.get("scan_id", type=int) or session.get("scan_id")
    if not scan_id or scan_id != session.get("scan_id"):
        abort(403)
    scan = db.get_scan(scan_id)
    if not scan:
        abort(404)

    findings    = scan["findings"]
    criticality = scan["criticality"]
    remediation = scan["remediation"]
    total       = scan["total_principals"]

    pdf_bytes = generate_pdf_report(findings, criticality, remediation, total)

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=iam_risk_report.pdf"},
    )


@app.route("/suppress", methods=["POST"])
@require_auth
@csrf_protect
def suppress_finding():
    data       = request.get_json(silent=True) or {}
    principal  = data.get("principal", "").strip()
    capability = data.get("capability", "").strip()
    reason     = _validate_reason(data.get("reason", "").strip())
    # H4: Validate length and format
    _validate_identifier(principal,  "principal")
    _validate_identifier(capability, "capability")
    db.add_suppression(principal, capability, reason)
    return jsonify({"status": "suppressed"})


@app.route("/suppressions")
@require_auth
def list_suppressions():
    return jsonify(db.list_suppressions())


@app.route("/suppress/<int:sup_id>", methods=["DELETE"])
@require_auth
@csrf_protect
def remove_suppression(sup_id: int):
    db.remove_suppression(sup_id)
    return jsonify({"status": "removed"})


@app.route("/history")
@require_auth
def history():
    return jsonify(db.list_scans())


@app.route("/history/<int:scan_id>")
@require_auth
def history_scan(scan_id: int):
    # M1: Only allow access to the current session's scan
    if scan_id != session.get("scan_id"):
        abort(403)
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)


@app.route("/compare")
@require_auth
def compare_scans():
    id_a = request.args.get("a", type=int)
    id_b = request.args.get("b", type=int)
    if not id_a or not id_b:
        return redirect("/history-page")
    result = db.compare_scans(id_a, id_b)
    if not result:
        return redirect("/history-page")
    return render_template("compare.html", **result)


@app.route("/api/notes", methods=["GET"])
@require_auth
def get_notes():
    return jsonify(db.get_finding_notes())


@app.route("/api/notes", methods=["POST"])
@require_auth
@csrf_protect
def upsert_note():
    data       = request.get_json(silent=True) or {}
    principal  = data.get("principal", "").strip()
    capability = data.get("capability", "").strip()
    status     = data.get("status", "open").strip()
    note       = data.get("note", "").strip()[:1000]
    _validate_identifier(principal,  "principal")
    _validate_identifier(capability, "capability")
    if status not in _STATUS_OK:
        return jsonify({"error": "invalid status"}), 400
    db.upsert_finding_note(principal, capability, status, note)
    return jsonify({"status": "saved"})


@app.route("/api/notes", methods=["DELETE"])
@require_auth
@csrf_protect
def delete_note():
    data       = request.get_json(silent=True) or {}
    principal  = data.get("principal", "").strip()
    capability = data.get("capability", "").strip()
    _validate_identifier(principal,  "principal")
    _validate_identifier(capability, "capability")
    db.delete_finding_note(principal, capability)
    return jsonify({"status": "deleted"})


@app.route("/scan/<int:scan_id>", methods=["DELETE"])
@require_auth
@csrf_protect
def delete_scan(scan_id: int):
    # H7: Only allow deleting the current session's scan
    if scan_id != session.get("scan_id"):
        abort(403)
    db.delete_scan(scan_id)
    session.pop("scan_id", None)
    return jsonify({"status": "deleted"})


@app.route("/scans/all", methods=["DELETE"])
@require_auth
@csrf_protect
def delete_all_scans():
    count = db.delete_all_scans()
    session.pop("scan_id", None)
    return jsonify({"status": "deleted", "count": count})


@app.route("/scan/<int:scan_id>/rename", methods=["PATCH"])
@require_auth
@csrf_protect
def rename_scan(scan_id: int):
    # H7: Only allow renaming the current session's scan
    if scan_id != session.get("scan_id"):
        abort(403)
    data     = request.get_json(silent=True) or {}
    new_name = data.get("name", "").strip()[:256]
    if not new_name:
        return jsonify({"error": "name is required"}), 400
    updated = db.rename_scan(scan_id, new_name)
    if not updated:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({"status": "renamed", "name": new_name})


@app.route("/api/trend")
@require_auth
def trend_data():
    return jsonify(db.get_trend_data())


@app.route("/api/remediate", methods=["POST"])
@require_auth
@csrf_protect
def ai_remediate():
    """
    Call Gemini to generate plain-English explanation + remediation for a finding.
    Requires GEMINI_API_KEY environment variable (free tier at aistudio.google.com).
    """
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        return jsonify({"error": "GEMINI_API_KEY not configured on this server."}), 503

    import requests as _requests

    data       = request.get_json(silent=True) or {}
    principal  = data.get("principal", "Unknown")
    capability = data.get("capability", "Unknown")
    severity   = data.get("severity", "Unknown")
    risk       = data.get("risk", 0)
    path       = data.get("path", [])
    pattern    = data.get("pattern", "")
    mitre      = data.get("mitre", "")
    cross_acct = data.get("cross_account", False)
    conditions = data.get("condition_flags", {})

    path_str = " → ".join(path) if path else "N/A"
    cond_summary = []
    if conditions.get("requires_mfa"):          cond_summary.append("MFA required")
    if conditions.get("requires_external_id"):   cond_summary.append("ExternalId required")
    if conditions.get("source_ip_restricted"):   cond_summary.append("Source IP restricted")
    if conditions.get("org_id_required"):        cond_summary.append("Org ID required")
    if conditions.get("region_restricted"):      cond_summary.append("Region restricted")
    cond_str = ", ".join(cond_summary) if cond_summary else "None"

    prompt = f"""You are an AWS IAM security expert. Analyze this privilege escalation finding and provide actionable remediation.

FINDING:
- Principal: {principal}
- Escalation Capability: {capability}
- Severity: {severity} (Risk Score: {risk}/100)
- Attack Pattern: {pattern}
- MITRE ATT&CK: {mitre}
- Cross-Account: {cross_acct}
- Trust Conditions on Path: {cond_str}
- Escalation Path: {path_str}

Respond with EXACTLY this JSON structure (no markdown, no extra text):
{{
  "explanation": "2-3 sentence plain-English explanation of what this vulnerability means and how an attacker would exploit it",
  "impact": "1-2 sentences on the business/security impact if exploited",
  "remediation_steps": ["step 1", "step 2", "step 3"],
  "iam_policy_fix": "JSON IAM policy statement that removes or restricts the dangerous permission",
  "terraform_snippet": "Terraform HCL snippet to implement the fix (or empty string if not applicable)"
}}"""

    try:
        url  = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-lite:generateContent"
        body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": 1024},
        }
        # H3: Pass key in header, not URL param (prevents logging in proxy/access logs)
        resp = _requests.post(url, json=body, headers={"x-goog-api-key": api_key}, timeout=30)
        resp.raise_for_status()
        raw  = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
        # Strip markdown code fences if Gemini wraps the JSON
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()
        result = json.loads(raw)
        return jsonify(result)
    except json.JSONDecodeError:
        return jsonify({"explanation": raw, "remediation_steps": [], "iam_policy_fix": "", "terraform_snippet": ""})
    except Exception:
        log.exception("AI remediation call failed")
        return jsonify({"error": "AI remediation is temporarily unavailable."}), 500


# ── M4: Security response headers ─────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
    # CSP: allow inline styles/scripts (needed for vis-network + Chart.js inline usage)
    response.headers["Content-Security-Policy"]   = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self';"
    )
    return response


# ── Startup ───────────────────────────────────────────────────────────────────

db.init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # C4: Never enable Flask debug mode — it exposes an interactive code console
    app.run(debug=False, host="127.0.0.1", port=port)
