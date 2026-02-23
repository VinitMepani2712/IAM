from flask import Flask, render_template, request
import json
from cloud.aws.parser import parse_aws_iam_json
from simulation.enterprise_generator import generate_enterprise_environment
from engine.analyzer import analyze_environment_data
from engine.analyzer import build_attack_graph, extract_graph_data
from graph.attack_graph import build_attack_graph

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    # -----------------------------------------
    #  Load principals
    # -----------------------------------------
    if "file" in request.files and request.files["file"].filename != "":
        file = request.files["file"]
        data = json.load(file)
        principals = parse_aws_iam_json(data)

    elif request.form.get("simulate"):
        principals = generate_enterprise_environment(
            num_accounts=5,
            roles_per_account=50,
            users_per_account=10
        )

    else:
        return "No input provided", 400

    # -----------------------------------------
    #  Run Analyzer
    # -----------------------------------------
    findings, criticality, remediation = analyze_environment_data(principals)
    top_critical = list(criticality.items())[:5] if criticality else []
    top_critical_ids = [node for node, _ in top_critical[:3]]    
    

    # -----------------------------------------
    #  Build Graph Data
    # -----------------------------------------
    graph = build_attack_graph(principals)

    # Escalation-only view
    nodes, edges = extract_graph_data(
        graph,
        findings=findings,
        escalation_only=True
    )

    # Full topology view
    full_nodes, full_edges = extract_graph_data(
        graph,
        findings=findings,
        escalation_only=False
    )

    # -----------------------------------------
    #  Render Dashboard
    # -----------------------------------------
    return render_template(
        "dashboard.html",
        findings=findings,
        criticality=criticality,
        top_critical = top_critical,
        top_critical_ids = top_critical_ids,
        nodes=nodes,
        edges=edges,
        full_nodes=full_nodes,
        full_edges=full_edges,
        remediation=remediation
    )

if __name__ == "__main__":
    app.run(debug=True)