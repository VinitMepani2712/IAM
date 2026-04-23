# IAM Defender — AWS IAM Privilege Escalation Detection Engine

A full-stack web application that automatically detects multi-hop privilege escalation paths in AWS IAM configurations, maps attack graphs, scores risk, and generates prioritized remediation plans.

---

## Table of Contents

- [What It Does](#what-it-does)
- [How It Works](#how-it-works)
- [Features](#features)
- [Architecture](#architecture)
- [Detection Capabilities](#detection-capabilities)
- [Risk Scoring](#risk-scoring)
- [Attack Patterns & MITRE ATT&CK](#attack-patterns--mitre-attck)
- [Setup — Local](#setup--local)
- [Setup — Render (Cloud)](#setup--render-cloud)
- [Environment Variables](#environment-variables)
- [Project Structure](#project-structure)
- [Tech Stack](#tech-stack)
- [Security Hardening](#security-hardening)

---

## What It Does

IAM Defender takes an AWS IAM export (`GetAccountAuthorizationDetails` JSON) and:

1. Parses every user, role, group, and attached policy
2. Builds a directed attack graph of privilege escalation paths
3. Scores each path by risk (0–100) and classifies severity (CRITICAL / HIGH / MEDIUM / LOW)
4. Maps findings to MITRE ATT&CK techniques
5. Identifies the minimum set of policy changes that would eliminate the most attack paths
6. Optionally generates AI-powered plain-English explanations and remediation steps using Google Gemini

---

## How It Works

### Step 1 — Upload

Upload the JSON output of:
```bash
aws iam get-account-authorization-details --output json > iam_export.json
```

### Step 2 — Parse

`cloud/aws/parser.py` reads:
- `UserDetailList` — IAM users with attached/inline policies
- `RoleDetailList` — IAM roles with trust policies and permission boundaries
- `GroupDetailList` — Groups and their members
- `Policies` — Managed policy documents

Each principal is converted into a `Principal` entity with resolved policy statements, trust conditions (MFA required, ExternalId, source IP restrictions, Org ID), and permission boundaries.

### Step 3 — Build Attack Graph

`graph/attack_graph.py` builds a directed graph where:
- **Nodes** are principals (users, roles), intermediate action nodes (`ACTION::`), and capability nodes (`CAPABILITY::`)
- **Edges** represent "can reach" relationships — a principal with `sts:AssumeRole` permission on a role gets an edge to that role

The graph uses an adjacency list with sets (O(1) deduplication).

### Step 4 — Find Escalation Paths

`graph/reachability.py` runs DFS with backtracking from every principal to find all simple paths that terminate at a `CAPABILITY::` node. Each path represents a concrete multi-hop attack sequence.

```
SecurityUser1 → ACTION::iam:PassRole → DevRole → CAPABILITY::FULL_ADMIN
```

### Step 5 — Score & Classify

`analysis/risk_model.py` computes a 0–100 risk score per finding based on capability class, path length, cross-account pivot, and trust conditions on the path.

### Step 6 — Remediation

`analysis/min_cut.py` computes the weighted minimum cut of the attack graph — the smallest set of nodes (policy actions) whose removal eliminates the most escalation paths.

`analysis/dominator.py` finds dominator nodes — every attack path passes through these, making them high-priority remediation targets.

### Step 7 — Display

Results are rendered in a full-featured web dashboard with an interactive attack graph, sortable findings table, AI remediation panel, and PDF/JSON/CSV export.

---

## Features

### Analysis Engine
- Multi-hop privilege escalation detection (up to 10 hops deep)
- Cross-account pivot detection
- Trust condition analysis (MFA, ExternalId, source IP, Org ID, region restrictions)
- Permission boundary enforcement
- SCP (Service Control Policy) deny evaluation
- Dominator node analysis — nodes every attack path flows through
- Weighted minimum cut — fewest changes to break the most paths
- Suppression / false-positive management

### Attack Graph (vis.js)
- Force-physics layout with forceAtlas2Based solver
- **Tree View toggle** — snaps nodes into 3 clean columns: Principal → Action → Capability
- **Severity-colored node borders** — orange = HIGH, yellow = MEDIUM, green = LOW, full red = top critical
- Node types: Principals (blue circles), Actions (purple boxes), Capabilities (green diamonds)
- Severity filter chips (All / Critical / High / Medium / Low)
- Path isolator — click any finding to highlight its exact attack path on the graph
- Attack simulation mode — animates escalation paths step by step with a status banner
- Escalation view vs. Full topology toggle
- Export graph as PNG image
- Click any node to filter the findings table to matching rows

### Findings Dashboard
- Sortable table with risk score bars, severity pills, MITRE ATT&CK tags
- Inline finding notes and status tracking (Open / Investigating / In Remediation / Accepted Risk)
- **NEW badge** on findings that did not exist in the user's previous scan
- Bulk select and export selected findings
- Search by principal name, action, or capability
- Filter by severity and attack pattern

### User Accounts & History
- Multi-user registration and login
- Each user's scan history is private — other users cannot access it
- Public analysis — no login required to run a scan; login required to save and view history
- Scan history page with risk trend chart (Chart.js line chart)
- Scan comparison — select any 2 scans to diff side by side (new / fixed / worse / better findings)
- Scan rename and individual or bulk delete
- Search and filter history by filename and severity

### Export
- **JSON** — full findings data
- **CSV** — spreadsheet-compatible findings export
- **PDF** — formatted risk report (ReportLab)

---

## Architecture

```
Browser
   │
   ▼
Flask (app.py)
   ├── /                    Upload page (public)
   ├── /analyze             POST — runs full analysis pipeline (public)
   ├── /dashboard           GET  — view current scan results
   ├── /history-page        GET  — scan history (login required)
   ├── /compare             GET  — diff two scans
   ├── /principal/<name>    GET  — principal detail view
   ├── /api/trend           GET  — risk trend data for Chart.js
   ├── /export/json         GET  — download findings as JSON
   ├── /export/pdf          GET  — download PDF report
   ├── /health              GET  — uptime check (for Render)
   ├── /login  /register  /logout
   └── /scan/<id>  DELETE  /scan/<id>/rename  PATCH
        │
        ▼
   Analysis Pipeline
   ├── cloud/aws/parser.py          — parse IAM JSON export
   ├── graph/attack_graph.py        — build directed attack graph
   ├── graph/reachability.py        — DFS escalation path finder
   ├── engine/analyzer.py           — orchestrate full analysis
   ├── analysis/risk_model.py       — risk scoring (0–100)
   ├── analysis/attack_patterns.py  — MITRE ATT&CK classification
   ├── analysis/centrality.py       — node centrality scoring
   ├── analysis/min_cut.py          — minimum cut remediation
   ├── analysis/dominator.py        — dominator node analysis
   └── analysis/criticality.py      — node criticality ranking
        │
        ▼
   SQLite (iam_defender.db)
   ├── users                — registered accounts (bcrypt-hashed passwords)
   ├── scans                — scan metadata per user
   ├── scan_findings        — serialised findings JSON
   ├── scan_remediation     — remediation data
   ├── scan_graph           — graph node/edge data for replay
   ├── finding_notes        — inline notes and status per finding
   ├── suppressions         — false-positive suppressions
   └── ai_remediation_cache — cached Gemini responses (keyed by SHA-256)
```

---

## Detection Capabilities

| Capability Class | AWS Actions Detected |
|---|---|
| `FULL_ADMIN` | `AdministratorAccess` managed policy |
| `ROLE_ASSUMPTION` | `sts:AssumeRole`, `sts:AssumeRoleWithWebIdentity` |
| `PRIVILEGE_PROPAGATION` | `iam:PassRole`, `iam:AddUserToGroup`, `iam:UpdateAssumeRolePolicy`, `iam:DeleteRolePermissionsBoundary`, `iam:DeleteUserPermissionsBoundary` |
| `POLICY_MODIFICATION` | `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:AttachUserPolicy`, `iam:PutUserPolicy`, `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion` |
| `ACCESS_KEY_PERSISTENCE` | `iam:CreateAccessKey` |
| `CONSOLE_ACCESS` | `iam:CreateLoginProfile`, `iam:UpdateLoginProfile` |
| `COMPUTE_LAUNCH` | `ec2:RunInstances`, `lambda:CreateFunction`, `lambda:UpdateFunctionCode`, `glue:CreateJob`, `cloudformation:CreateStack`, `ecs:RunTask`, `sagemaker:CreateTrainingJob` |
| `IDENTITY_CREATION` | `iam:CreateUser`, `iam:CreateRole` |
| `DATA_READ` | `s3:GetObject`, `s3:ListBucket` |
| `AUDIT_READ` | `cloudtrail:LookupEvents` |
| `LOG_ACCESS` | `logs:GetLogEvents`, `logs:DescribeLogGroups` |
| `RECON` | `iam:ListRoles`, `iam:GetRole`, `iam:SimulatePrincipalPolicy` |

---

## Risk Scoring

Every finding is scored 0–100:

| Factor | Impact on Score |
|--------|----------------|
| Capability class (FULL_ADMIN = highest) | Base score (1–100) |
| Path length (shorter = less detectable) | −3 per extra hop beyond 2 |
| Cross-account pivot | +15 |
| MFA required on path | −10 |
| Source IP restricted | −8 |
| ExternalId required | −6 |
| Org ID required | −5 |
| Region restricted | −4 |

**Severity thresholds:**

| Score | Severity |
|-------|----------|
| ≥ 80 | CRITICAL |
| ≥ 55 | HIGH |
| ≥ 30 | MEDIUM |
| < 30  | LOW |

---

## Attack Patterns & MITRE ATT&CK

| Pattern | MITRE Technique |
|---|---|
| `PASSROLE_COMPUTE_EXECUTION` | T1098.001 — Account Manipulation: Additional Cloud Credentials |
| `POLICY_MANIPULATION` | T1098 — Account Manipulation |
| `PRIVILEGE_AMPLIFICATION` | T1078.004 — Valid Accounts: Cloud Accounts |
| `PERSISTENCE_VIA_ACCESS_KEY` | T1098.001 — Account Manipulation: Additional Cloud Credentials |
| `IDENTITY_CREATION_ABUSE` | T1136.003 — Create Account: Cloud Account |
| `CROSS_ACCOUNT_PIVOT` | T1199 — Trusted Relationship |
| `ROLE_CHAINING` | T1078.004 — Valid Accounts: Cloud Accounts |
| `CONSOLE_TAKEOVER` | T1098 — Account Manipulation |

---

## Setup — Local

### Prerequisites

- Python 3.11+
- pip

### Install

```bash
git clone https://github.com/VinitMepani2712/IAM.git
cd IAM
pip install -r requirements.txt
```

### Configure

```bash
cp .env.example .env
```

Edit `.env`:

```env
# Required — generate a random key:
# python -c "import secrets; print(secrets.token_hex(32))"
IAM_SECRET_KEY=your-random-secret-here

# Optional — for AI remediation
GEMINI_API_KEY=your-gemini-key-here
```

### Run

```bash
python app.py
```

Open `http://localhost:5000`

### Get an IAM Export to Test With

```bash
aws iam get-account-authorization-details --output json > my_iam.json
```

Upload `my_iam.json` on the home page. No login required to run a scan. Create an account to save scan history.

---

## Setup — Render (Cloud)

The project includes `render.yaml` for Render deployment via Docker.

1. Push the repository to GitHub
2. Go to [render.com](https://render.com) → **New Web Service** → connect your repo
3. In your service → **Environment** tab, add these variables:

| Key | Value |
|-----|-------|
| `IAM_SECRET_KEY` | Run `python -c "import secrets; print(secrets.token_hex(32))"` locally and paste the output |
| `GEMINI_API_KEY` | Your Gemini API key (optional) |

4. Click **Save Changes** → Render redeploys automatically

> The app will crash on startup if `IAM_SECRET_KEY` is not set. This is intentional — a missing secret key means sessions are insecure.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `IAM_SECRET_KEY` | **Yes** | Flask session secret key. App refuses to start without it. Generate with `python -c "import secrets; print(secrets.token_hex(32))"` |
| `IAM_DB_PATH` | No | SQLite database file path. Default: `iam_defender.db` |
| `IAM_LOG_LEVEL` | No | Logging level: `DEBUG` / `INFO` / `WARNING` / `ERROR`. Default: `INFO` |
| `IAM_HTTPS` | No | Set to `1` to enable `Secure` flag on session cookies (use when behind HTTPS proxy) |
| `PORT` | No | Server port. Default: `5000` |

---

## Project Structure

```
IAM/
├── app.py                    # Flask app — all routes, auth, CSRF, security headers
├── db.py                     # SQLite persistence layer (all DB functions)
├── logging_config.py         # Structured JSON logging setup
├── requirements.txt
├── render.yaml               # Render deployment config
├── Dockerfile
├── .env.example              # Environment variable template
│
├── core/
│   ├── entities.py           # Principal, PolicyStatement, TrustCondition dataclasses
│   ├── privilege_model.py    # IAM action → Capability class mapping + weights
│   └── state_engine.py       # Policy evaluation state machine
│
├── cloud/
│   └── aws/
│       └── parser.py         # Parses GetAccountAuthorizationDetails JSON
│
├── graph/
│   ├── attack_graph.py       # Builds directed attack graph (adjacency list + sets)
│   ├── reachability.py       # DFS path finder with depth + time guard
│   └── traversal.py          # Graph traversal utilities
│
├── engine/
│   └── analyzer.py           # Orchestrates the full analysis pipeline
│
├── analysis/
│   ├── risk_model.py         # Risk score formula (0–100) + severity thresholds
│   ├── attack_patterns.py    # MITRE ATT&CK pattern classification
│   ├── centrality.py         # Escalation path centrality scoring
│   ├── min_cut.py            # Weighted minimum cut for optimal remediation
│   ├── dominator.py          # Dominator node analysis
│   ├── criticality.py        # Per-node criticality ranking
│   ├── dashboard.py          # Dashboard data aggregation helpers
│   └── remediation.py        # Remediation suggestion generation
│
├── pdf/
│   └── pdf_report.py         # PDF risk report generation (ReportLab)
│
├── templates/
│   ├── index.html            # Upload & analyze page
│   ├── dashboard.html        # Main results dashboard + graph + findings table
│   ├── history.html          # User scan history with trend chart
│   ├── compare.html          # Side-by-side scan comparison / diff
│   ├── principal.html        # Per-principal detail view
│   ├── login.html            # Login page (split-screen design)
│   └── register.html         # Account registration page
│
└── static/
    ├── dashboard.css         # Dashboard + all inner pages (dark/light mode)
    └── index.css             # Upload page styles (dark/light mode)
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, Flask 3.0 |
| Database | SQLite via Python stdlib `sqlite3` |
| Graph engine | Custom adjacency-list DFS — no external graph library |
| Frontend | Vanilla JavaScript |
| Graph visualization | vis.js (force physics + manual tree layout) |
| Charts | Chart.js 4 |
| PDF export | ReportLab 4 |
| Password hashing | Werkzeug PBKDF2-SHA256 |
| Deployment | Docker, Render, gunicorn (Linux/production) |

---

## Security Hardening

| Control | Implementation |
|---|---|
| CSRF protection | `X-CSRF-Token` header required on all POST/PATCH/DELETE routes, validated against session token |
| Session security | `HttpOnly=True`, `SameSite=Strict`, configurable `Secure` flag |
| Fail-fast secret key | App raises `RuntimeError` on startup if `IAM_SECRET_KEY` is not set |
| Generic error messages | Internal exceptions logged server-side only — users see generic messages |
| File upload safety | `werkzeug.utils.secure_filename`, content-type validation, JSON schema check |
| Security response headers | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `X-XSS-Protection: 1; mode=block`, `Referrer-Policy: strict-origin-when-cross-origin`, `Content-Security-Policy` |
| API key protection | Gemini key sent in `x-goog-api-key` header, never in URL (prevents proxy log exposure) |
| AI response caching | Identical findings served from SQLite cache (SHA-256 keyed), not re-queried |
| XSS prevention | Chart.js data injected via `json.dumps()` in template, not raw interpolation |


