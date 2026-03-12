from flask import Flask, render_template, request, jsonify, Response, session
import json
import io
from datetime import datetime

from cloud.aws.parser import parse_aws_iam_json
from engine.analyzer import analyze_environment_data, extract_graph_data
from graph.attack_graph import build_attack_graph
from pdf.pdf_report import generate_pdf_report

app = Flask(__name__)
app.secret_key = "iam-defender-secret-2024"   # needed for session


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    #  Load principals ─
    if "file" not in request.files or request.files["file"].filename == "":
        return render_template("index.html", error="Please upload an IAM JSON file.")

    file = request.files["file"]

    try:
        data = json.load(file)
    except json.JSONDecodeError as e:
        return render_template("index.html", error=f"Invalid JSON file: {e}")

    try:
        principals = parse_aws_iam_json(data)
    except Exception as e:
        return render_template("index.html", error=f"Failed to parse IAM data: {e}")

    if not principals:
        return render_template("index.html", error="No IAM principals found in the uploaded file.")

    #  Run analysis 
    findings, criticality, remediation = analyze_environment_data(principals)

    top_critical    = list(criticality.items())[:5] if criticality else []
    top_critical_ids = [node for node, _ in top_critical[:3]]

    #  Build graph 
    graph = build_attack_graph(principals)
    nodes,      edges      = extract_graph_data(graph, findings=findings, escalation_only=True)
    full_nodes, full_edges = extract_graph_data(graph, findings=findings, escalation_only=False)

    #  Persist findings in session for export routes ─
    # Strip non-serialisable set objects from the path list
    session["findings"]    = findings
    session["criticality"] = {k: float(v) for k, v in criticality.items()}
    session["remediation"] = {
        "total_paths":       remediation["total_paths"],
        "recommended_fixes": [list(e) if isinstance(e, tuple) else e
                              for e in remediation["recommended_fixes"]],
        "dominators":        list(remediation["dominators"])
                              if hasattr(remediation["dominators"], "__iter__")
                              else [],
    }
    session["total_principals"] = len(principals)

    #  Render dashboard 
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
    )


# 
# Export: JSON
# 

@app.route("/export/json")
def export_json():
    findings    = session.get("findings", [])
    criticality = session.get("criticality", {})
    remediation = session.get("remediation", {})
    total       = session.get("total_principals", 0)

    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high     = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium   = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low      = sum(1 for f in findings if f.get("severity") == "LOW")

    report = {
        "generated_at":    datetime.utcnow().isoformat() + "Z",
        "tool":            "IAM Defender — Privilege Escalation Detection Engine",
        "summary": {
            "total_principals":   total,
            "total_findings":     len(findings),
            "critical":           critical,
            "high":               high,
            "medium":             medium,
            "low":                low,
            "cross_account":      sum(1 for f in findings if f.get("cross_account")),
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


# 
# Export: PDF
# 

@app.route("/export/pdf")
def export_pdf():
    findings    = session.get("findings", [])
    criticality = session.get("criticality", {})
    remediation = session.get("remediation", {})
    total       = session.get("total_principals", 0)

    pdf_bytes = generate_pdf_report(findings, criticality, remediation, total)

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=iam_risk_report.pdf"},
    )


if __name__ == "__main__":
    app.run(debug=True)