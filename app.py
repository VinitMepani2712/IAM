from flask import Flask, render_template, request, Response, session, jsonify, redirect
import json
import logging
import os
from datetime import datetime, timezone

from logging_config import setup_logging
setup_logging()

log = logging.getLogger(__name__)

from cloud.aws.parser import parse_aws_iam_json
from engine.analyzer import analyze_environment_data, extract_graph_data
from graph.attack_graph import build_attack_graph
from pdf.pdf_report import generate_pdf_report
import db

app = Flask(__name__)
app.secret_key = os.environ.get("IAM_SECRET_KEY", "iam-defender-dev-key-change-in-prod")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    if "file" not in request.files or request.files["file"].filename == "":
        return render_template("index.html", error="Please upload an IAM JSON file.")

    file     = request.files["file"]
    filename = file.filename or "upload.json"

    try:
        data = json.load(file)
    except json.JSONDecodeError as e:
        return render_template("index.html", error=f"Invalid JSON file: {e}")

    try:
        principals, scps, _resource_policies = parse_aws_iam_json(data)
    except Exception as e:
        log.exception("Failed to parse IAM data from '%s'", filename)
        return render_template("index.html", error=f"Failed to parse IAM data: {e}")

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
        log.exception("Could not save scan to database — falling back to session storage")

    # Keep in session as fast-access fallback
    session["findings"]         = findings
    session["criticality"]      = {k: float(v) for k, v in criticality.items()}
    session["remediation"]      = remediation_serial
    session["total_principals"] = len(principals)

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
def history_page():
    return render_template("history.html", scans=db.list_scans())


@app.route("/principal/<path:principal_name>")
def principal_detail(principal_name: str):
    scan_id = request.args.get("scan_id", type=int) or session.get("scan_id")
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
def export_json():
    # Allow ?scan_id=X to pull a specific historical scan
    scan_id = request.args.get("scan_id", type=int) or session.get("scan_id")
    scan    = db.get_scan(scan_id) if scan_id else None

    findings    = scan["findings"]         if scan else session.get("findings", [])
    criticality = scan["criticality"]      if scan else session.get("criticality", {})
    remediation = scan["remediation"]      if scan else session.get("remediation", {})
    total       = scan["total_principals"] if scan else session.get("total_principals", 0)

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
def export_pdf():
    scan_id = request.args.get("scan_id", type=int) or session.get("scan_id")
    scan    = db.get_scan(scan_id) if scan_id else None

    findings    = scan["findings"]         if scan else session.get("findings", [])
    criticality = scan["criticality"]      if scan else session.get("criticality", {})
    remediation = scan["remediation"]      if scan else session.get("remediation", {})
    total       = scan["total_principals"] if scan else session.get("total_principals", 0)

    pdf_bytes = generate_pdf_report(findings, criticality, remediation, total)

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=iam_risk_report.pdf"},
    )


@app.route("/suppress", methods=["POST"])
def suppress_finding():
    data       = request.get_json(silent=True) or {}
    principal  = data.get("principal", "").strip()
    capability = data.get("capability", "").strip()
    reason     = data.get("reason", "").strip()
    if not principal or not capability:
        return jsonify({"error": "principal and capability are required"}), 400
    db.add_suppression(principal, capability, reason)
    return jsonify({"status": "suppressed"})


@app.route("/suppressions")
def list_suppressions():
    return jsonify(db.list_suppressions())


@app.route("/suppress/<int:sup_id>", methods=["DELETE"])
def remove_suppression(sup_id: int):
    db.remove_suppression(sup_id)
    return jsonify({"status": "removed"})


@app.route("/history")
def history():
    """Return JSON list of all past scans, newest first."""
    return jsonify(db.list_scans())


@app.route("/history/<int:scan_id>")
def history_scan(scan_id: int):
    """Return full findings for a past scan by ID."""
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)


@app.route("/compare")
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
def get_notes():
    return jsonify(db.get_finding_notes())


@app.route("/api/notes", methods=["POST"])
def upsert_note():
    data       = request.get_json(silent=True) or {}
    principal  = data.get("principal", "").strip()
    capability = data.get("capability", "").strip()
    status     = data.get("status", "open").strip()
    note       = data.get("note", "").strip()
    if not principal or not capability:
        return jsonify({"error": "principal and capability required"}), 400
    if status not in ("open", "in_remediation", "accepted_risk", "investigating"):
        return jsonify({"error": "invalid status"}), 400
    db.upsert_finding_note(principal, capability, status, note)
    return jsonify({"status": "saved"})


@app.route("/api/notes", methods=["DELETE"])
def delete_note():
    data       = request.get_json(silent=True) or {}
    principal  = data.get("principal", "").strip()
    capability = data.get("capability", "").strip()
    if not principal or not capability:
        return jsonify({"error": "principal and capability required"}), 400
    db.delete_finding_note(principal, capability)
    return jsonify({"status": "deleted"})


@app.route("/scan/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id: int):
    db.delete_scan(scan_id)
    return jsonify({"status": "deleted"})


@app.route("/scans/all", methods=["DELETE"])
def delete_all_scans():
    count = db.delete_all_scans()
    return jsonify({"status": "deleted", "count": count})


@app.route("/scan/<int:scan_id>/rename", methods=["PATCH"])
def rename_scan(scan_id: int):
    data     = request.get_json(silent=True) or {}
    new_name = data.get("name", "").strip()
    if not new_name:
        return jsonify({"error": "name is required"}), 400
    updated = db.rename_scan(scan_id, new_name)
    if not updated:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({"status": "renamed", "name": new_name})


@app.route("/api/trend")
def trend_data():
    """Return per-scan severity counts for the trend chart (oldest→newest)."""
    return jsonify(db.get_trend_data())


@app.route("/api/remediate", methods=["POST"])
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
        resp = _requests.post(url, json=body, params={"key": api_key}, timeout=30)
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
    except Exception as e:
        log.exception("AI remediation call failed")
        return jsonify({"error": str(e)}), 500


# ── Startup ───────────────────────────────────────────────────────────────────

db.init_db()

if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("IAM_LOG_LEVEL", "INFO").upper() == "DEBUG"
    app.run(debug=debug, port=port)
