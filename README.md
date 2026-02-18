project:
  name: "IAM Attack Graph Analyzer"
  tagline: "Scalable IAM privilege escalation detection using graph-based authorization modeling and dominance-pruned reachability."
  author:
    name: "Vinit Mepani"
    degree: "MSCS"
    focus: "Security Engineering"

executive_summary:
  problem_statement: >
    Modern cloud IAM environments contain complex, interdependent policies.
    Privilege escalation often emerges from multi-step permission chains rather
    than a single overly permissive policy.
  solution: >
    This project models IAM as a state transition system and constructs an
    explicit attack graph to detect multi-hop privilege escalation paths.
  capabilities:
    - "Formal IAM semantic modeling"
    - "Explicit attack graph construction"
    - "Multi-hop escalation detection"
    - "Environment-wide escalation audit"
    - "Centrality-based bottleneck analysis"
    - "Cost-aware remediation ranking"
    - "Attack graph visualization"
    - "Scalability benchmarking"

design_philosophy:
  core_idea: >
    Instead of scanning policies individually, the system models IAM
    authorization as a directed state transition graph and solves
    the privilege escalation safety problem via reachability analysis.
  escalation_definition: >
    Escalation exists if a principal can reach a critical capability
    that it did not already directly possess.

architecture:
  pipeline:
    - "IAM JSON Input"
    - "Semantic Authorization Evaluator"
    - "Attack Graph Construction"
    - "Dominance-Pruned Reachability Engine"
    - "Centrality + Remediation Analysis"
    - "Visualization + Reporting"
  modules:
    models: "IAM entity definitions"
    semantics: "Authorization evaluation engine"
    graph: "Attack graph construction and traversal"
    analysis: "Centrality, remediation, visualization"
    benchmarks: "Scalability performance testing"
    parsers: "AWS IAM JSON ingestion"
    cli: "Multi-mode execution via main.py"

core_features:
  formal_authorization_modeling:
    - "Explicit deny precedence"
    - "AssumeRole trust evaluation"
    - "PassRole + service pivot abstraction"
    - "Critical privilege classification"
  multi_hop_detection:
    description: "Detects chained escalation paths across roles."
    example_path:
      - "UserA"
      - "RoleDev"
      - "RoleAdmin"
      - "CAPABILITY::AdministratorAccess"
  environment_wide_audit:
    output_example:
      principal_summary:
        - principal: "UserA"
          escalation_paths: 1
        - principal: "RoleDev"
          escalation_paths: 1
  centrality_analysis:
    formula: >
      Centrality(role) =
      (# escalation paths through role) /
      (total escalation paths)
    purpose: "Identify trust bottlenecks and high-risk IAM roles."
  remediation_ranking:
    ranking_basis:
      - "Frequency across escalation paths"
      - "Operational disruption cost"
    example:
      - edge: "('UserA', 'RoleDev')"
        priority_score: 0.5
      - edge: "('RoleDev', 'RoleAdmin')"
        priority_score: 0.5
      - edge: "('RoleAdmin', 'CAPABILITY::AdministratorAccess')"
        priority_score: 0.2
  visualization:
    highlights:
      - "Directed graph rendering"
      - "Escalation path highlighted in red"
      - "Critical capability nodes highlighted in orange"
      - "Presentation-ready attack chain display"
  scalability:
    complexity_estimate: "Approximately O(V + E)"
    benchmark_features:
      - "Graph construction runtime"
      - "Reachability performance"
      - "Execution time vs role count"

usage:
  synthetic_demo: "python main.py"
  full_environment_audit: "python main.py aws_sample.json"
  specific_principal_analysis: "python main.py aws_sample.json UserA"
  scalability_benchmark: "python main.py --benchmark"

security_foundations:
  inspirations:
    - "Attack graph modeling (Sheyner et al.)"
    - "Access control safety problem"
    - "Graph-based vulnerability propagation"
    - "State transition system modeling in security engineering"

technical_highlights:
  - "Dominance-pruned BFS traversal"
  - "Graph-based privilege propagation modeling"
  - "Trust relationship risk evaluation"
  - "Centrality-driven influence scoring"
  - "Cost-aware remediation prioritization"
  - "Scalable CLI-based multi-mode execution"

future_improvements:
  - "Condition-key semantic modeling"
  - "Resource-level privilege reasoning"
  - "Cross-account trust analysis"
  - "Minimal cut-set computation"
  - "Interactive web-based graph visualization"
  - "Memory complexity benchmarking"
