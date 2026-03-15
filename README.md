# IAM Attack Graph Analyzer

> A scalable IAM privilege escalation detection engine using graph-based
> authorization modeling and dominance-pruned reachability analysis.

---

## Executive Summary

Modern cloud IAM environments often contain hundreds or thousands of
interdependent policies. Privilege escalation frequently emerges not
from a single overly permissive policy, but from **multi-step chains of
legitimate permissions** such as AssumeRole chaining and PassRole abuse.

This project implements a **formal attack-graph-based IAM analysis engine** that:

- Models AWS IAM authorization semantics
- Constructs an explicit directed attack graph
- Detects multi-hop privilege escalation paths
- Performs environment-wide escalation audits
- Ranks escalation bottlenecks via centrality metrics
- Suggests cost-aware remediation strategies
- Visualizes escalation chains
- Exports professional PDF and JSON risk reports
- Benchmarks scalability at enterprise scale

---

## Design Philosophy

Instead of scanning policies individually, this engine:

1. Models IAM as a **state transition system**
2. Constructs an explicit directed authorization graph
3. Computes attacker-reachable critical capabilities
4. Applies dominance-pruned graph traversal
5. Performs security-impact-driven remediation ranking

Escalation is strictly defined as:

> A principal gaining access to a critical capability that it did not
> already directly possess.

---

## Architecture

```
IAM JSON / Live AWS
       ↓
cloud/aws/parser.py  —  Semantic Authorization Evaluator
       ↓
graph/attack_graph.py  —  Attack Graph Construction
       ↓
graph/reachability.py  —  Dominance-Pruned Reachability
       ↓
analysis/  —  Centrality + Risk Scoring + Remediation
       ↓
pdf/pdf_report.py  +  templates/  —  Reporting & Dashboard
```

### Module Map

| Directory | Purpose |
|---|---|
| `core/` | IAM entity dataclasses (`Principal`, `PolicyStatement`, `TrustCondition`) and privilege capability map |
| `cloud/aws/` | AWS IAM JSON parser, live boto3 fetcher, semantic evaluator, resource policy model |
| `graph/` | Attack graph construction, BFS reachability, general traversal utilities |
| `engine/` | Full-environment analysis pipeline (used by the web app) |
| `analysis/` | Risk scoring, attack pattern classification, centrality, dominators, minimal cut, remediation, visualization, dashboard |
| `pdf/` | Professional ReportLab PDF report generator |
| `simulation/` | Synthetic enterprise IAM environment generator |
| `benchmarks/` | Scalability and accuracy benchmarks |
| `templates/` | Flask Jinja2 HTML templates |
| `static/` | CSS for the web dashboard |

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Usage

### Web App (recommended)

```bash
python app.py
# then open http://127.0.0.1:5000 and upload an IAM JSON file
```

Set `IAM_SECRET_KEY` in your environment before running in production:

```bash
export IAM_SECRET_KEY="your-random-secret"
python app.py
```

### CLI — Full Environment Audit

```bash
python main.py aws_export.json
```

### CLI — Deep Dive on One Principal

```bash
python main.py aws_export.json UserA
```

### CLI — Export PDF Report

```bash
python main.py aws_export.json --pdf
```

### CLI — Live AWS Fetch

```bash
python main.py --live
python main.py --live --profile dev UserA
```

### CLI — Enterprise Simulation Demo

```bash
python main.py --simulate
python main.py --simulate --pdf
```

---

## Multi-Hop Privilege Escalation Detection

Example escalation chain:

```
UserA → RoleDev → RoleAdmin → CAPABILITY::FULL_ADMIN
```

Features:

- Explicit AssumeRole transition modeling
- PassRole + service pivot abstraction
- MFA / ExternalId condition mitigation
- Minimal path reconstruction
- Multi-hop chaining support

---

## Environment-Wide Escalation Audit

```
=== Full Environment Escalation Audit ===

Principal | Escalation | Risk | Severity | Cross-Account | Pattern | MITRE
--------------------------------------------------------------------------------
UserA     | FULL_ADMIN | 90.0 | CRITICAL | False | PRIVILEGE_AMPLIFICATION | ...
RoleDev   | POLICY_MODIFICATION | 65.0 | HIGH | False | POLICY_MANIPULATION | ...
```

---

## Escalation Centrality Analysis

```
Centrality(role) =
    (# escalation paths through role) /
    (total escalation paths)
```

---

## Ranked Remediation Suggestions

Example:

```
Remove edge ('UserA', 'RoleDev')              | Priority Score: 0.5
Remove edge ('RoleDev', 'RoleAdmin')          | Priority Score: 0.5
Remove edge ('RoleAdmin', 'CAPABILITY::...')  | Priority Score: 0.2
```

---

## Attack Graph Visualization

- Directed graph rendering via NetworkX + Matplotlib
- Escalation paths highlighted in red
- Critical capability nodes highlighted in orange

---

## Scalability Benchmarking

Demonstrates near O(V + E) behavior in graph construction and traversal.

```bash
python -m benchmarks.scalability
```

---

## Author

**Vinit Mepani**
ECE 507 — Security Engineering, Sem 3
