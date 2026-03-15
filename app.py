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
        principals = parse_aws_iam_json(data)
    except Exception as e:
        log.exception("Failed to parse IAM data from '%s'", filename)
        return render_template("index.html", error=f"Failed to parse IAM data: {e}")

    if not principals:
        return render_template("index.html", error="No IAM principals found in the uploaded file.")

    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Run analysis
    findings, criticality, remediation = analyze_environment_data(principals)

    # Filter out suppressed (false-positive) findings
    try:
        suppressed = {(s["principal"], s["capability"]) for s in db.list_suppressions()}
        findings = [f for f in findings
                    if (f.get("principal", ""), f.get("capability", "")) not in suppressed]
    except Exception:
        log.warning("Could not apply suppressions — showing all findings")

    top_critical     = list(criticality.items())[:5] if criticality else []
    top_critical_ids = [node for node, _ in top_critical[:3]]

    # Build graph data
    graph = build_attack_graph(principals)
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
    )


@app.route("/history-page")
def history_page():
    return render_template("history.html", scans=db.list_scans())


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


# ── Startup ───────────────────────────────────────────────────────────────────

db.init_db()

if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("IAM_LOG_LEVEL", "INFO").upper() == "DEBUG"
    app.run(debug=debug, port=port)
