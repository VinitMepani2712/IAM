import json


def generate_risk_report(findings, output_file="risk_report.json"):

    report = {
        "summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW")
        },
        "findings": findings
    }

    with open(output_file, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\nRisk report written to {output_file}")
