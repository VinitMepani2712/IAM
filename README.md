🚀 IAM Attack Graph Analyzer

A scalable IAM privilege escalation detection engine using graph-based authorization modeling and dominance-pruned reachability analysis.

🔐 Overview

Modern cloud IAM environments contain hundreds or thousands of interdependent policies. Privilege escalation often emerges not from a single overly permissive policy, but from multi-step chains of legitimate permissions (e.g., AssumeRole chaining, PassRole abuse).

This project implements a formal attack-graph-based IAM analysis engine that:

Models AWS IAM authorization semantics

Constructs an explicit attack graph

Detects multi-hop privilege escalation paths

Ranks escalation bottlenecks via centrality metrics

Suggests cost-aware remediation strategies

Visualizes escalation chains

Benchmarks scalability at enterprise scale

🧠 Key Features
✅ Formal Authorization Modeling

Explicit deny precedence

Role trust evaluation

AssumeRole transition modeling

PassRole + service pivot modeling

Critical privilege classification

🔎 Multi-Hop Privilege Escalation Detection

Detects escalation chains such as:

UserA → RoleDev → RoleAdmin → AdministratorAccess


Uses:

Explicit graph construction

Dominance-pruned BFS

Minimal path reconstruction

📊 Environment-Wide Escalation Audit

Scans all IAM principals and reports:

Which principals can escalate

Number of escalation paths

Ranked severity

Example output:

=== Full Environment Escalation Audit ===

Principal | Escalation Path Count
----------------------------------
UserA     | 1
RoleDev   | 1

📈 Escalation Centrality Analysis

Identifies trust bottlenecks by computing:

Centrality(role) = \frac{\text{# paths through role}}{\text{total escalation paths}}

Helps security teams prioritize high-risk roles.

🛠 Ranked Remediation Suggestions

Recommends edge removals ranked by:

Frequency across escalation paths

Operational cost modeling

Example:

Remove edge ('UserA', 'RoleDev') | Priority Score: 0.5

🎨 Attack Graph Visualization

Directed graph visualization

Escalation path highlighted in red

Critical capability nodes highlighted in orange

Provides intuitive visual analysis of attack chains.

⚙️ Scalability Benchmarking

Includes runtime benchmarking module to evaluate:

Graph construction performance

Reachability scaling behavior

Execution time vs number of roles

Demonstrates near O(V+E) behavior.

🏗 Architecture
IAM JSON → Semantic Evaluator → Attack Graph → Reachability Engine
                                          ↓
                               Centrality + Remediation
                                          ↓
                                    Visualization


Core modules:

models/ — IAM entity modeling

semantics/ — Authorization evaluation

graph/ — Attack graph construction + traversal

analysis/ — Centrality, remediation, visualization

benchmarks/ — Scalability testing

parsers/ — AWS IAM JSON ingestion

🚀 Usage
Synthetic Demo
python main.py

Full Environment Audit
python main.py aws_sample.json

Analyze Specific Principal
python main.py aws_sample.json UserA

Run Scalability Benchmark
python main.py --benchmark

📌 Example Escalation Path
UserA → RoleDev → RoleAdmin → CAPABILITY::AdministratorAccess

🔬 Research Foundations

Inspired by:

Attack graph analysis (Sheyner et al.)

Access control safety problem

Graph reachability modeling in security systems

🎯 Why This Project Matters

Traditional IAM compliance tools evaluate policies individually.

This engine instead models:

IAM as a state transition system and solves the safety problem via graph reachability.

It detects escalation chains that static rule-based tools may miss.

📦 Future Improvements

Condition-key modeling

Resource-level privilege reasoning

Cross-account trust analysis

Interactive web-based visualization

Minimal cut-set computation