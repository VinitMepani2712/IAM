from collections import Counter
from analysis.min_cut import compute_weighted_minimal_cut
from analysis.dominator import compute_dominators


def generate_global_dashboard(principals, findings, criticality=None, output_file="dashboard.html"):

    total_principals = len(principals)
    total_findings = len(findings)

    severity_counts = Counter(f["severity"] for f in findings)
    pattern_counts = Counter(f["attack_pattern"] for f in findings)

    vulnerable_principals = set(f["principal"] for f in findings)

    cross_account_count = sum(1 for f in findings if f.get("cross_account"))

    # Most abused actions
    action_counter = Counter()
    for f in findings:
        for node in f["path"]:
            if node.startswith("ACTION::"):
                action_counter[node] += 1

    top_actions = action_counter.most_common(5)

    # Global paths
    all_paths = [f["path"] for f in findings]

    global_dominators = compute_dominators(all_paths) if all_paths else []
    global_cut = compute_weighted_minimal_cut(all_paths) if all_paths else []

    top_critical = list(criticality.items())[:5] if criticality else []

    html = f"""
    <html>
    <head>
        <title>IAM Global Risk Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{
                font-family: Arial;
                background-color: #0f172a;
                color: white;
                padding: 40px;
            }}
            .card {{
                background: #1e293b;
                padding: 20px;
                margin-bottom: 25px;
                border-radius: 10px;
            }}
            h1 {{
                color: #38bdf8;
            }}
            h2 {{
                margin-top: 0;
                color: #facc15;
            }}
        </style>
    </head>
    <body>

        <h1>IAM Attack Surface Intelligence Dashboard</h1>

        <div class="card">
            <h2>Environment Overview</h2>
            <p>Total Principals: {total_principals}</p>
            <p>Total Findings: {total_findings}</p>
            <p>Vulnerable Principals: {len(vulnerable_principals)}</p>
            <p>Cross-Account Escalations: {cross_account_count}</p>
        </div>

        <div class="card">
            <h2>🔥 Top Risk Drivers (Structural Criticality)</h2>
            <ul>
                {''.join(f"<li>{node} → {round(score,2)}</li>" for node, score in top_critical)}
            </ul>
        </div>

        <div class="card">
            <h2>Most Abused Actions</h2>
            <ul>
                {''.join(f"<li>{action} → {count} paths</li>" for action, count in top_actions)}
            </ul>
        </div>

        <div class="card">
            <h2>Global Structural Choke Points (Dominators)</h2>
            <ul>
                {''.join(f"<li>{node}</li>" for node in global_dominators)}
            </ul>
        </div>

        <div class="card">
            <h2>Global Weighted Minimal Remediation Set</h2>
            <ul>
                {''.join(f"<li>{edge}</li>" for edge in global_cut)}
            </ul>
        </div>

        <div class="card">
            <h2>Severity Distribution</h2>
            <canvas id="severityChart"></canvas>
        </div>

        <div class="card">
            <h2>Attack Pattern Distribution</h2>
            <canvas id="patternChart"></canvas>
        </div>

        <script>
            new Chart(document.getElementById('severityChart'), {{
                type: 'pie',
                data: {{
                    labels: {list(severity_counts.keys())},
                    datasets: [{{
                        data: {list(severity_counts.values())},
                        backgroundColor: ['#ef4444','#f97316','#facc15','#22c55e']
                    }}]
                }}
            }});

            new Chart(document.getElementById('patternChart'), {{
                type: 'bar',
                data: {{
                    labels: {list(pattern_counts.keys())},
                    datasets: [{{
                        data: {list(pattern_counts.values())},
                        backgroundColor: '#38bdf8'
                    }}]
                }}
            }});
        </script>

    </body>
    </html>
    """

    with open(output_file, "w") as f:
        f.write(html)