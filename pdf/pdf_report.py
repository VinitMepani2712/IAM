"""
pdf/pdf_report.py
Professional IAM Risk Intelligence Report

Structure:
  Page 1  — Cover (hero card, 3×2 stat grid, scope table)
  Page 2  — Executive Summary (narrative, top nodes, attack patterns)
  Page 3  — Remediation Plan (choke points + ordered fix set)
  Page 4+ — All Findings (5-column, stacked cells)
"""

import io
from datetime import datetime
from collections import Counter

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, PageBreak, HRFlowable,
)

# ─────────────────────────────────────────────────────────────────────────────
# Page geometry
# ─────────────────────────────────────────────────────────────────────────────
PW, PH = A4                     # 595.27 × 841.89 pt
LM = 1.8 * cm
RM = 1.8 * cm
TM = 2.6 * cm                  # room for header band
BM = 2.0 * cm
CW = PW - LM - RM              # ≈ 451 pt usable width

# ─────────────────────────────────────────────────────────────────────────────
# Palette
# ─────────────────────────────────────────────────────────────────────────────
NAVY        = colors.HexColor("#0f172a")
NAVY2       = colors.HexColor("#1e293b")
NAVY3       = colors.HexColor("#273549")
BLUE        = colors.HexColor("#2563eb")
BLUE_LT     = colors.HexColor("#eff6ff")
BLUE_MID    = colors.HexColor("#dbeafe")
RED         = colors.HexColor("#dc2626")
RED_LT      = colors.HexColor("#fef2f2")
ORANGE      = colors.HexColor("#ea580c")
ORANGE_LT   = colors.HexColor("#fff7ed")
YELLOW      = colors.HexColor("#ca8a04")
YELLOW_LT   = colors.HexColor("#fefce8")
GREEN       = colors.HexColor("#16a34a")
GREEN_LT    = colors.HexColor("#f0fdf4")
PURPLE      = colors.HexColor("#7c3aed")
PURPLE_LT   = colors.HexColor("#f5f3ff")
WHITE       = colors.HexColor("#ffffff")
OFF_WHITE   = colors.HexColor("#f8fafc")
SURFACE     = colors.HexColor("#f1f5f9")
TEXT        = colors.HexColor("#0f172a")
TEXT_SOFT   = colors.HexColor("#475569")
TEXT_MUTED  = colors.HexColor("#94a3b8")
BORDER      = colors.HexColor("#e2e8f0")
BORDER_DARK = colors.HexColor("#cbd5e1")

GEN_TS = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
GEN_D  = datetime.utcnow().strftime("%Y-%m-%d")

# ─────────────────────────────────────────────────────────────────────────────
# Severity helpers
# ─────────────────────────────────────────────────────────────────────────────
def sev_fg(s):
    return {"CRITICAL": RED, "HIGH": ORANGE,
            "MEDIUM":  YELLOW, "LOW": GREEN}.get(s, TEXT_MUTED)

def sev_bg(s):
    return {"CRITICAL": RED_LT,    "HIGH": ORANGE_LT,
            "MEDIUM":   YELLOW_LT, "LOW":  GREEN_LT}.get(s, OFF_WHITE)

def sev_border(s):
    return {"CRITICAL": colors.HexColor("#fca5a5"),
            "HIGH":     colors.HexColor("#fdba74"),
            "MEDIUM":   colors.HexColor("#fde047"),
            "LOW":      colors.HexColor("#86efac")}.get(s, BORDER)

def compute_risk_grade(findings):
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high     = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium   = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low      = sum(1 for f in findings if f.get("severity") == "LOW")
    score    = min(100, critical * 25 + high * 10 + medium * 3 + low)
    if score >= 80: return score, "F", "Critical Risk",  RED
    if score >= 60: return score, "D", "Very High Risk", ORANGE
    if score >= 40: return score, "C", "High Risk",      YELLOW
    if score >= 20: return score, "B", "Moderate Risk",  BLUE
    return score, "A", "Low Risk", GREEN

def strip_prefix(n):
    return (n.replace("CAPABILITY::", "")
             .replace("ACTION::", "")
             .replace("iam:PassRole+", "PassRole+"))

def fmt_path(path):
    return "  →  ".join(strip_prefix(n) for n in path)


# ─────────────────────────────────────────────────────────────────────────────
# Style factory
# ─────────────────────────────────────────────────────────────────────────────
def S(size=9, color=TEXT, align=TA_LEFT, bold=False,
      leading=None, after=2, font=None):
    fn = font or ("Helvetica-Bold" if bold else "Helvetica")
    return ParagraphStyle(
        "_",
        fontName=fn,
        fontSize=size,
        textColor=color,
        alignment=align,
        leading=leading or size * 1.45,
        spaceAfter=after,
    )

def mono(size=8, color=TEXT_SOFT, align=TA_LEFT):
    return ParagraphStyle(
        "_",
        fontName="Courier",
        fontSize=size,
        textColor=color,
        alignment=align,
        leading=size * 1.4,
        spaceAfter=0,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Table cell helpers
# ─────────────────────────────────────────────────────────────────────────────
def th(text, align=TA_CENTER):
    return Paragraph(
        text,
        ParagraphStyle("_th", fontName="Helvetica-Bold", fontSize=8,
                       textColor=WHITE, alignment=align, leading=11),
    )

def td(text, size=9, color=TEXT, align=TA_LEFT, bold=False, courier=False):
    fn = "Courier" if courier else ("Helvetica-Bold" if bold else "Helvetica")
    return Paragraph(
        str(text),
        ParagraphStyle("_td", fontName=fn, fontSize=size, textColor=color,
                       alignment=align, leading=size * 1.4, spaceAfter=0),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Modern table style: horizontal rules only (no vertical grid lines)
# ─────────────────────────────────────────────────────────────────────────────
def clean_ts(n_data_rows, header_bg=NAVY2, row_pad=7, col_pad=9):
    ts = TableStyle([
        # Header background
        ("BACKGROUND",    (0, 0), (-1, 0), header_bg),
        # Only horizontal separators
        ("LINEBELOW",     (0, 0), (-1, -2), 0.35, BORDER),
        ("LINEBELOW",     (0,-1), (-1, -1), 0.35, BORDER),
        ("LINEABOVE",     (0, 0), (-1,  0), 0.35, BORDER_DARK),
        # Padding
        ("TOPPADDING",    (0, 0), (-1, -1), row_pad),
        ("BOTTOMPADDING", (0, 0), (-1, -1), row_pad),
        ("LEFTPADDING",   (0, 0), (-1, -1), col_pad),
        ("RIGHTPADDING",  (0, 0), (-1, -1), col_pad),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ])
    for i in range(1, n_data_rows + 1):
        ts.add("BACKGROUND", (0, i), (-1, i),
               SURFACE if i % 2 == 0 else WHITE)
    return ts


# ─────────────────────────────────────────────────────────────────────────────
# Severity badge (pill-shaped coloured tag)
# ─────────────────────────────────────────────────────────────────────────────
def sev_badge(sev):
    return Table(
        [[Paragraph(sev,
                    ParagraphStyle("_sb", fontName="Helvetica-Bold",
                                   fontSize=7, textColor=sev_fg(sev),
                                   alignment=TA_CENTER, leading=9))]],
        colWidths=[1.6 * cm],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), sev_bg(sev)),
            ("BOX",           (0, 0), (-1, -1), 0.6, sev_border(sev)),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
            ("ROUNDEDCORNERS", [4]),
        ]),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Callout box
# ─────────────────────────────────────────────────────────────────────────────
def callout(text, bg=BLUE_LT, border=BLUE, icon=None):
    content = f"{icon}  {text}" if icon else text
    return Table(
        [[Paragraph(content, S(size=9.5, leading=16))]],
        colWidths=[CW],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), bg),
            ("LINEBEFORE",    (0, 0), (0,  -1), 3.5, border),
            ("TOPPADDING",    (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ("LEFTPADDING",   (0, 0), (-1, -1), 14),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
        ]),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Section heading — large title, accent underline, optional subtitle
# ─────────────────────────────────────────────────────────────────────────────
def section_head(title, subtitle=None):
    els = [
        Spacer(1, 0.1 * cm),
        Paragraph(title, S(size=16, color=NAVY, bold=True,
                           leading=21, after=4)),
        HRFlowable(width=CW, thickness=2, color=BLUE,
                   spaceAfter=0, spaceBefore=2),
    ]
    if subtitle:
        els.append(Paragraph(subtitle,
                             S(size=9, color=TEXT_SOFT, leading=14, after=2)))
    els.append(Spacer(1, 0.28 * cm))
    return els


def subsection(title):
    return [
        Paragraph(title, S(size=11, color=NAVY2, bold=True,
                           leading=16, after=3)),
        HRFlowable(width=CW, thickness=0.6, color=BORDER_DARK,
                   spaceAfter=0, spaceBefore=1),
        Spacer(1, 0.12 * cm),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Page header / footer callbacks
# ─────────────────────────────────────────────────────────────────────────────
def _draw_page_header_footer(canvas, doc):
    canvas.saveState()

    # 4 pt accent bar at very top
    canvas.setFillColor(BLUE)
    canvas.rect(0, PH - 4, PW, 4, fill=1, stroke=0)

    # Header band
    canvas.setFillColor(OFF_WHITE)
    canvas.rect(0, PH - 32, PW, 28, fill=1, stroke=0)
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.4)
    canvas.line(LM, PH - 32, PW - RM, PH - 32)

    canvas.setFillColor(NAVY)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(LM, PH - 22, "IAM RISK INTELLIGENCE REPORT")

    canvas.setFillColor(TEXT_SOFT)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(LM + 188, PH - 22, "Privilege Escalation Analysis")

    canvas.setFillColor(BLUE)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawRightString(PW - RM, PH - 22, f"Page {doc.page}")

    # Footer
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.4)
    canvas.line(LM, 26, PW - RM, 26)

    canvas.setFillColor(TEXT_MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(LM, 14, "Confidential  ·  IAM Defender  ·  Internal Use Only")
    canvas.drawRightString(PW - RM, 14, GEN_D)

    canvas.restoreState()


def _draw_cover_footer(canvas, _doc):
    canvas.saveState()
    canvas.setFillColor(BLUE)
    canvas.rect(0, PH - 4, PW, 4, fill=1, stroke=0)
    canvas.setFillColor(TEXT_MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawCentredString(PW / 2, 14,
        f"Confidential  ·  IAM Defender  ·  {GEN_TS}")
    canvas.restoreState()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 1 — Cover
# ─────────────────────────────────────────────────────────────────────────────
def build_cover(findings, remediation, total_principals):
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high     = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium   = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low      = sum(1 for f in findings if f.get("severity") == "LOW")
    cross    = sum(1 for f in findings if f.get("cross_account"))
    total_f  = len(findings)
    n_fixes  = len(remediation.get("recommended_fixes", []))
    affected = len(set(f.get("principal", "") for f in findings))
    patterns = Counter(f.get("pattern", "") for f in findings)
    top_pat  = (patterns.most_common(1)[0][0].replace("_", " ")
                if patterns else "N/A")

    risk_score, risk_grade, risk_label, risk_color = compute_risk_grade(findings)

    els = []

    # ── Hero block ────────────────────────────────────────────────────────────
    title_block = [
        Paragraph(
            "IAM Risk Intelligence Report",
            ParagraphStyle("_ht", fontName="Helvetica-Bold", fontSize=24,
                           textColor=WHITE, leading=30, spaceAfter=8)),
        Paragraph(
            "Privilege Escalation &amp; Attack Surface Analysis",
            ParagraphStyle("_hs", fontName="Helvetica", fontSize=11,
                           textColor=colors.HexColor("#94a3b8"),
                           leading=17, spaceAfter=6)),
        Paragraph(
            f"Generated: {GEN_TS}",
            ParagraphStyle("_hd", fontName="Helvetica", fontSize=8.5,
                           textColor=colors.HexColor("#64748b"), leading=13)),
    ]

    # Risk grade circle (right side)
    grade_block = Table(
        [
            [Paragraph(risk_grade,
                       ParagraphStyle("_gr", fontName="Helvetica-Bold",
                                      fontSize=52, textColor=risk_color,
                                      alignment=TA_CENTER, leading=58))],
            [Paragraph(risk_label,
                       ParagraphStyle("_gl", fontName="Helvetica-Bold",
                                      fontSize=8.5, textColor=risk_color,
                                      alignment=TA_CENTER, leading=13))],
            [Paragraph(f"Score: {risk_score}/100",
                       ParagraphStyle("_gs", fontName="Helvetica",
                                      fontSize=7.5,
                                      textColor=colors.HexColor("#64748b"),
                                      alignment=TA_CENTER, leading=12))],
        ],
        colWidths=[3.4 * cm],
        style=TableStyle([
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]),
    )

    hero = Table(
        [[title_block, grade_block]],
        colWidths=[CW - 3.8 * cm, 3.8 * cm],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), NAVY),
            ("LEFTPADDING",   (0, 0), (0,  -1), 26),
            ("RIGHTPADDING",  (0, 0), (0,  -1), 12),
            ("LEFTPADDING",   (1, 0), (1,  -1), 6),
            ("RIGHTPADDING",  (1, 0), (1,  -1), 20),
            ("TOPPADDING",    (0, 0), (-1, -1), 28),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 28),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ROUNDEDCORNERS", [8]),
        ]),
    )
    els.append(hero)
    els.append(Spacer(1, 0.5 * cm))

    # ── Stat grid: 3 cards × 2 rows ───────────────────────────────────────────
    card_w = CW / 3

    def stat_card(value, label, val_color):
        rows = [
            [Paragraph(str(value),
                       ParagraphStyle("_cv", fontName="Helvetica-Bold",
                                      fontSize=28, textColor=val_color,
                                      alignment=TA_CENTER, leading=33))],
            [Paragraph(label,
                       ParagraphStyle("_cl", fontName="Helvetica",
                                      fontSize=8, textColor=TEXT_SOFT,
                                      alignment=TA_CENTER, leading=12))],
        ]
        return Table(
            rows,
            colWidths=[card_w - 0.3 * cm],
            style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), WHITE),
                ("BOX",           (0, 0), (-1, -1), 0.5, BORDER),
                ("TOPPADDING",    (0, 0), (-1, -1), 14),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
                ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
                ("ROUNDEDCORNERS", [7]),
            ]),
        )

    row1 = [
        stat_card(total_principals, "Principals Scanned", BLUE),
        stat_card(total_f,          "Total Findings",     TEXT),
        stat_card(affected,         "Principals Affected", PURPLE),
    ]
    card_w4 = CW / 4
    row2 = [
        stat_card(critical, "Critical", RED),
        stat_card(high,     "High",     ORANGE),
        stat_card(medium,   "Medium",   YELLOW),
        stat_card(low,      "Low",      GREEN),
    ]
    grid_style = TableStyle([
        ("LEFTPADDING",  (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ])
    els.append(Table([row1], colWidths=[card_w] * 3, style=grid_style))
    els.append(Spacer(1, 0.2 * cm))
    els.append(Table([row2], colWidths=[card_w4] * 4, style=grid_style))
    els.append(Spacer(1, 0.4 * cm))

    # ── Cross-account alert ───────────────────────────────────────────────────
    if cross > 0:
        els.append(callout(
            f'<font color="#dc2626"><b>{cross} Cross-Account Escalation'
            f'{"s" if cross > 1 else ""} Detected.</b></font>  '
            '<font color="#475569">These paths traverse AWS account boundaries '
            'and significantly expand the blast radius. Prioritise immediately.'
            '</font>',
            bg=RED_LT, border=RED,
        ))
        els.append(Spacer(1, 0.3 * cm))

    # ── Scope summary table ───────────────────────────────────────────────────
    els += subsection("Scan Summary")

    scope_data = [
        [th("Metric", TA_LEFT),          th("Value", TA_LEFT)],
        [td("Overall Risk Grade",        bold=True),
         td(f"{risk_grade}  —  {risk_label}  (score {risk_score}/100)",
            bold=True, color=risk_color)],
        [td("Total Principals Scanned",  bold=True), td(str(total_principals), bold=True, color=BLUE)],
        [td("Principals with Escalation Paths", bold=True), td(str(affected), bold=True, color=BLUE)],
        [td("Total Escalation Paths",    bold=True), td(str(total_f),          bold=True, color=BLUE)],
        [td("Critical  /  High",         bold=True),
         td(f"{critical}  /  {high}",    bold=True,
            color=RED if critical else ORANGE)],
        [td("Most Prevalent Pattern",    bold=True), td(top_pat,   color=TEXT_SOFT)],
        [td("Cross-Account Paths",       bold=True),
         td(str(cross), bold=True, color=RED if cross else GREEN)],
        [td("Minimal Remediation Actions", bold=True),
         td(str(n_fixes), bold=True, color=ORANGE)],
    ]
    els.append(Table(
        scope_data,
        colWidths=[CW * 0.6, CW * 0.4],
        style=clean_ts(len(scope_data) - 1),
    ))

    els.append(PageBreak())
    return els


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 2 — Executive Summary
# ─────────────────────────────────────────────────────────────────────────────
def build_exec_summary(findings, criticality):
    els = []
    els += section_head("Executive Summary")

    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    total    = len(findings)
    affected = len(set(f.get("principal", "") for f in findings))
    patterns = Counter(f.get("pattern", "") for f in findings)
    top_pat  = (patterns.most_common(1)[0][0].replace("_", " ")
                if patterns else "N/A")

    els.append(callout(
        f"This report identifies <b>{total} privilege escalation "
        f"path{'s' if total != 1 else ''}</b> across "
        f"<b>{affected} IAM principal{'s' if affected != 1 else ''}</b>. "
        f"<b>{critical}</b> finding{'s are' if critical != 1 else ' is'} rated "
        f'<font color="#dc2626"><b>CRITICAL</b></font> and require '
        f"immediate action. The most prevalent attack technique is <b>{top_pat}</b>.",
    ))
    els.append(Spacer(1, 0.5 * cm))

    # ── Top 10 Critical Nodes ─────────────────────────────────────────────────
    els += subsection("Top 10 Critical Nodes")
    els.append(Paragraph(
        "Ranked by structural criticality — frequency of appearance across "
        "escalation paths, weighted by average risk score.",
        S(size=9, color=TEXT_SOFT, leading=14, after=6),
    ))

    top_nodes = list(criticality.items())[:10]
    node_rows = [[th("#", TA_CENTER), th("Node", TA_LEFT),
                  th("Type", TA_CENTER), th("Criticality Score", TA_CENTER)]]
    for rank, (node, score) in enumerate(top_nodes, 1):
        if "CAPABILITY::" in node:
            ntype, nc = "Capability", GREEN
        elif "ACTION::" in node:
            ntype, nc = "Action",     PURPLE
        else:
            ntype, nc = "Principal",  BLUE
        node_rows.append([
            td(str(rank), align=TA_CENTER, color=TEXT_MUTED),
            td(strip_prefix(node), bold=True, size=8),
            td(ntype, align=TA_CENTER, size=8, color=nc),
            td(f"{score:.1f}", align=TA_CENTER, size=11, bold=True, color=BLUE),
        ])
    els.append(Table(
        node_rows,
        colWidths=[1.2*cm, 9.8*cm, 2.4*cm, 3.0*cm],
        style=clean_ts(len(node_rows) - 1),
        repeatRows=1,
    ))
    els.append(Spacer(1, 0.5 * cm))

    # ── Attack Pattern Breakdown ──────────────────────────────────────────────
    els += subsection("Attack Pattern Breakdown")
    els.append(Paragraph(
        "Distribution of detected MITRE ATT&amp;CK-aligned attack techniques.",
        S(size=9, color=TEXT_SOFT, leading=14, after=6),
    ))

    MITRE_MAP = {
        "PASSROLE_COMPUTE_EXECUTION": "T1098 — Account Manipulation",
        "POLICY_MANIPULATION":        "T1098 — Account Manipulation",
        "PRIVILEGE_AMPLIFICATION":    "T1078 — Valid Accounts",
        "CROSS_ACCOUNT_PIVOT":        "T1021 — Remote Services",
        "MULTI_HOP_LATERAL_MOVEMENT": "T1021 — Remote Services",
        "ROLE_ASSUMPTION_ABUSE":      "T1078 — Valid Accounts",
        "IDENTITY_CREATION_ABUSE":    "T1136 — Create Account",
        "PERSISTENCE_VIA_ACCESS_KEY": "T1098.001 — Additional Cloud Credentials",
        "GENERIC_ESCALATION":         "T1078 — Valid Accounts",
    }
    pat_rows = [[
        th("Attack Pattern",           TA_LEFT),
        th("Count",                    TA_CENTER),
        th("Share",                    TA_CENTER),
        th("MITRE ATT&amp;CK",         TA_LEFT),
    ]]
    for pat, cnt in patterns.most_common():
        pat_rows.append([
            td(pat.replace("_", " "), bold=True, size=8),
            td(str(cnt), align=TA_CENTER, size=11, bold=True, color=BLUE),
            td(f"{cnt / total * 100:.0f}%", align=TA_CENTER, size=9,
               color=TEXT_SOFT),
            td(MITRE_MAP.get(pat, "T1078 — Valid Accounts"),
               size=8, color=TEXT_SOFT),
        ])
    els.append(Table(
        pat_rows,
        colWidths=[5.8*cm, 1.6*cm, 1.6*cm, 7.4*cm],
        style=clean_ts(len(pat_rows) - 1),
        repeatRows=1,
    ))

    els.append(PageBreak())
    return els


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 3 — Remediation Plan
# ─────────────────────────────────────────────────────────────────────────────
def build_remediation(remediation):
    fixes      = remediation.get("recommended_fixes", [])
    dominators = list(remediation.get("dominators", []))
    total_p    = remediation.get("total_paths", 0)

    els = []
    els += section_head(
        "Remediation Plan",
        "Minimum IAM changes required to eliminate all detected escalation paths.",
    )

    els.append(callout(
        f"The minimal fix set contains <b>{len(fixes)} targeted "
        f"change{'s' if len(fixes) != 1 else ''}</b> that together eliminate "
        f"all <b>{total_p}</b> detected escalation "
        f"path{'s' if total_p != 1 else ''}. "
        "Apply changes in the order shown for maximum risk reduction per action.",
        bg=GREEN_LT, border=GREEN,
    ))
    els.append(Spacer(1, 0.45 * cm))

    # ── Structural choke points ───────────────────────────────────────────────
    if dominators:
        els += subsection("Structural Choke Points (Dominators)")
        els.append(Paragraph(
            "These nodes appear in every escalation path. "
            "Remediating them blocks all detected paths simultaneously.",
            S(size=9, color=TEXT_SOFT, leading=14, after=6),
        ))
        DOM_REC = {
            "sts:AssumeRole": "Restrict the downstream role trust policy to deny this principal",
            "iam:PassRole":   "Limit iam:PassRole to specific approved role ARNs only",
        }
        dom_rows = [[
            th("#", TA_CENTER),
            th("Choke Point Node", TA_LEFT),
            th("Type",            TA_CENTER),
            th("Recommended Action", TA_LEFT),
        ]]
        for i, d in enumerate(dominators, 1):
            ntype = ("Capability" if "CAPABILITY" in d
                     else "Action" if "ACTION" in d else "Principal")
            rec   = next((v for k, v in DOM_REC.items() if k in d),
                         "Remove or restrict this permission or trust relationship")
            dom_rows.append([
                td(str(i), align=TA_CENTER, color=TEXT_MUTED),
                td(strip_prefix(d), courier=True, size=8),
                td(ntype, align=TA_CENTER, size=8, color=TEXT_SOFT),
                td(rec,   size=8, color=TEXT_SOFT),
            ])
        els.append(Table(
            dom_rows,
            colWidths=[0.9*cm, 5.4*cm, 2.1*cm, 7.9*cm],
            style=clean_ts(len(dom_rows) - 1),
            repeatRows=1,
        ))
        els.append(Spacer(1, 0.5 * cm))

    # ── Ordered fix set ───────────────────────────────────────────────────────
    els += subsection("Ordered Minimal Fix Set")
    els.append(Paragraph(
        "Each entry removes one edge from the attack graph, "
        "covering all escalation paths with the fewest IAM policy changes.",
        S(size=9, color=TEXT_SOFT, leading=14, after=6),
    ))

    from analysis.remediation_cli import generate_cli_fixes
    cli_fixes = generate_cli_fixes(fixes)

    fix_rows = [[
        th("No.",            TA_CENTER),
        th("Source Node",    TA_LEFT),
        th("Target Node",    TA_LEFT),
        th("Action",         TA_LEFT),
        th("AWS CLI Command", TA_LEFT),
    ]]
    for i, cf in enumerate(cli_fixes, 1):
        src = str(cf["edge"][0])
        dst = str(cf["edge"][1]) if len(cf["edge"]) > 1 else ""
        cli_line = next(
            (ln.strip() for ln in cf["cli"].splitlines()
             if ln.strip() and not ln.strip().startswith("#")),
            cf["cli"].splitlines()[0].strip() if cf["cli"] else "",
        )
        fix_rows.append([
            td(str(i), align=TA_CENTER, color=TEXT_MUTED, bold=True),
            td(strip_prefix(src), courier=True, size=7),
            td(strip_prefix(dst), courier=True, size=7),
            td(cf["description"], size=7.5, color=TEXT_SOFT),
            td(cli_line, courier=True, size=6.5, color=PURPLE),
        ])
    els.append(Table(
        fix_rows,
        colWidths=[0.9*cm, 3.4*cm, 3.4*cm, 5.0*cm, 3.6*cm],
        style=clean_ts(len(fix_rows) - 1),
        repeatRows=1,
    ))

    els.append(PageBreak())
    return els


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 4+ — All Findings
# ─────────────────────────────────────────────────────────────────────────────
def build_findings(findings):
    els = []
    els += section_head(
        "Escalation Findings",
        f"Complete list of {len(findings)} detected privilege escalation paths, "
        "sorted by risk score (highest first).",
    )

    sorted_f = sorted(findings, key=lambda f: f.get("risk", 0), reverse=True)

    # 5 columns: # | Severity | Principal / Capability / Pattern | Risk | Path
    # Widths (pt) summing to CW ≈ 451
    col_w = [18, 55, 148, 34, 196]

    header = [
        th("#",                             TA_CENTER),
        th("Severity",                      TA_CENTER),
        th("Principal  /  Capability",      TA_LEFT),
        th("Risk",                          TA_CENTER),
        th("Escalation Path",               TA_LEFT),
    ]

    rows = [header]
    ts = TableStyle([
        ("BACKGROUND",    (0, 0), (-1,  0), NAVY2),
        ("LINEBELOW",     (0, 0), (-1, -2), 0.35, BORDER),
        ("LINEBELOW",     (0,-1), (-1, -1), 0.35, BORDER),
        ("LINEABOVE",     (0, 0), (-1,  0), 0.35, BORDER_DARK),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ])

    for i, f in enumerate(sorted_f, 1):
        sev   = f.get("severity", "")
        risk  = f.get("risk", 0)
        pat   = f.get("pattern", "").replace("_", " ")
        path  = fmt_path(f.get("path", []))
        fg    = sev_fg(sev)

        # Stacked cell: Principal (bold) / Capability / Pattern (muted purple)
        principal_cell = [
            Paragraph(
                f"<b>{f.get('principal', '')}</b>",
                ParagraphStyle("_p", fontName="Helvetica-Bold",
                               fontSize=8, textColor=TEXT, leading=11)),
            Paragraph(
                f.get("capability", "").replace("_", " "),
                ParagraphStyle("_c", fontName="Helvetica",
                               fontSize=7.5, textColor=TEXT_SOFT, leading=10.5)),
            Paragraph(
                pat,
                ParagraphStyle("_pat", fontName="Helvetica",
                               fontSize=7, textColor=PURPLE, leading=10)),
        ]

        rows.append([
            td(str(i), align=TA_CENTER, size=8, color=TEXT_MUTED),
            sev_badge(sev),
            principal_cell,
            Paragraph(
                f"<b>{risk:.0f}</b>",
                ParagraphStyle("_r", fontName="Helvetica-Bold",
                               fontSize=12, textColor=fg,
                               alignment=TA_CENTER, leading=15)),
            Paragraph(
                path,
                ParagraphStyle("_path", fontName="Courier",
                               fontSize=6.5, textColor=TEXT_SOFT,
                               leading=9.5)),
        ])
        ts.add("BACKGROUND", (0, i), (-1, i),
               SURFACE if i % 2 == 0 else WHITE)

    els.append(Table(rows, colWidths=col_w, style=ts, repeatRows=1))
    return els


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────
def generate_pdf_report(findings, criticality, remediation,
                        total_principals) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=LM,
        rightMargin=RM,
        topMargin=TM,
        bottomMargin=BM,
        title="IAM Risk Intelligence Report",
        author="IAM Defender",
    )

    story = []
    story += build_cover(findings, remediation, total_principals)
    story += build_exec_summary(findings, criticality)
    story += build_remediation(remediation)
    story += build_findings(findings)

    # End-of-report marker
    story.append(Spacer(1, 0.5 * cm))
    story.append(HRFlowable(width=CW, thickness=0.5, color=BORDER))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(
        f"End of Report  ·  IAM Defender  ·  {GEN_TS}",
        S(size=7.5, color=TEXT_MUTED, align=TA_CENTER),
    ))

    doc.build(
        story,
        onFirstPage=_draw_cover_footer,
        onLaterPages=_draw_page_header_footer,
    )
    return buf.getvalue()
