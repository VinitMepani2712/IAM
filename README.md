# 🚀 IAM Attack Graph Analyzer

> A scalable IAM privilege escalation detection engine using graph-based
> authorization modeling and dominance-pruned reachability analysis.

------------------------------------------------------------------------

## 🔐 Executive Summary

Modern cloud IAM environments often contain hundreds or thousands of
interdependent policies. Privilege escalation frequently emerges not
from a single overly permissive policy, but from **multi-step chains of
legitimate permissions** such as AssumeRole chaining and PassRole abuse.

This project implements a **formal attack-graph-based IAM analysis
engine** that:

-   Models AWS IAM authorization semantics
-   Constructs an explicit attack graph
-   Detects multi-hop privilege escalation paths
-   Performs environment-wide escalation audits
-   Ranks escalation bottlenecks via centrality metrics
-   Suggests cost-aware remediation strategies
-   Visualizes escalation chains
-   Benchmarks scalability at enterprise scale

------------------------------------------------------------------------

## 🧠 Design Philosophy

Instead of scanning policies individually, this engine:

1.  Models IAM as a **state transition system**
2.  Constructs an explicit directed authorization graph
3.  Computes attacker-reachable critical capabilities
4.  Applies dominance-pruned graph traversal
5.  Performs security-impact-driven remediation ranking

Escalation is strictly defined as:

> A principal gaining access to a critical capability that it did not
> already directly possess.

------------------------------------------------------------------------

## 🏗 Architecture

    IAM JSON
       ↓
    Semantic Authorization Evaluator
       ↓
    Attack Graph Construction
       ↓
    Dominance-Pruned Reachability
       ↓
    Centrality + Remediation Analysis
       ↓
    Visualization + Reporting

### Core Modules

-   `models/` --- IAM entity definitions\
-   `semantics/` --- Authorization evaluation engine\
-   `graph/` --- Attack graph construction & traversal\
-   `analysis/` --- Centrality, remediation, visualization\
-   `benchmarks/` --- Scalability performance testing\
-   `parsers/` --- AWS IAM JSON ingestion\
-   `main.py` --- CLI interface

------------------------------------------------------------------------

## 🔎 Multi-Hop Privilege Escalation Detection

Example escalation chain:

    UserA → RoleDev → RoleAdmin → CAPABILITY::AdministratorAccess

Features:

-   Explicit AssumeRole transition modeling
-   PassRole + service pivot abstraction
-   Deny precedence enforcement
-   Minimal path reconstruction
-   Multi-hop chaining support

------------------------------------------------------------------------

## 📊 Environment-Wide Escalation Audit

    === Full Environment Escalation Audit ===

    Principal | Escalation Path Count
    ----------------------------------
    UserA     | 1
    RoleDev   | 1

------------------------------------------------------------------------

## 📈 Escalation Centrality Analysis

    Centrality(role) =
        (# escalation paths through role) /
        (total escalation paths)

------------------------------------------------------------------------

## 🛠 Ranked Remediation Suggestions

Example:

    Remove edge ('UserA', 'RoleDev') | Priority Score: 0.5
    Remove edge ('RoleDev', 'RoleAdmin') | Priority Score: 0.5
    Remove edge ('RoleAdmin', 'CAPABILITY::AdministratorAccess') | Priority Score: 0.2

------------------------------------------------------------------------

## 🎨 Attack Graph Visualization

-   Directed graph rendering
-   Escalation path highlighted in red
-   Critical capability nodes highlighted in orange

------------------------------------------------------------------------

## ⚙️ Scalability Benchmarking

Demonstrates near:

    O(V + E)

behavior in attack graph construction and traversal.

Run:

    python main.py --benchmark

------------------------------------------------------------------------

## 🚀 Usage

### Synthetic Demo

    python main.py

### Full Environment Audit

    python main.py aws_sample.json

### Analyze Specific Principal

    python main.py aws_sample.json UserA

------------------------------------------------------------------------

## 🎯 Resume Summary

> Built a scalable IAM privilege escalation detection engine using
> graph-based authorization modeling, dominance-pruned reachability,
> centrality scoring, remediation ranking, visualization, and
> scalability benchmarking for enterprise-scale IAM environments.

------------------------------------------------------------------------

## 👨‍💻 Author

**Vinit Mepani**
