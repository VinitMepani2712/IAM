"""
export/pdf_report.py
Professional IAM Risk Intelligence Report

Structure:
  Page 1  — Cover (dark hero, 6 stat cards, scope table)
  Page 2  — Executive Summary (narrative, top nodes, attack patterns)
  Page 3  — Remediation Plan (choke points + ordered fix set)
  Page 4+ — All Findings (sorted by risk desc)
"""

import io
from datetime import datetime
from collections import Counter

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, PageBreak,
)

# ─────────────────────────────────────────────────────────────────────────────
# Page geometry
# ─────────────────────────────────────────────────────────────────────────────
PW, PH = A4                     # 595.27 x 841.89 pt
LM = 1.8 * cm
RM = 1.8 * cm
TM = 2.4 * cm                  # room for header band
BM = 2.0 * cm                  # room for footer band
CW = PW - LM - RM              # usable content width

# ─────────────────────────────────────────────────────────────────────────────
# Colours
# ─────────────────────────────────────────────────────────────────────────────
NAVY        = colors.HexColor("#0f172a")
NAVY2       = colors.HexColor("#1e293b")
BLUE        = colors.HexColor("#3b82f6")
BLUE_LT     = colors.HexColor("#eff6ff")
RED         = colors.HexColor("#ef4444")
RED_LT      = colors.HexColor("#fef2f2")
ORANGE      = colors.HexColor("#f97316")
ORANGE_LT   = colors.HexColor("#fff7ed")
YELLOW      = colors.HexColor("#eab308")
YELLOW_LT   = colors.HexColor("#fefce8")
GREEN       = colors.HexColor("#22c55e")
GREEN_LT    = colors.HexColor("#f0fdf4")
PURPLE      = colors.HexColor("#6366f1")
WHITE       = colors.HexColor("#ffffff")
OFF_WHITE   = colors.HexColor("#f8fafc")
TEXT        = colors.HexColor("#1e293b")
TEXT_SOFT   = colors.HexColor("#475569")
MUTED       = colors.HexColor("#94a3b8")
BORDER      = colors.HexColor("#e2e8f0")

GEN_TS = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
GEN_D  = datetime.utcnow().strftime("%Y-%m-%d")

# ─────────────────────────────────────────────────────────────────────────────
# Tiny helpers
# ─────────────────────────────────────────────────────────────────────────────
def sev_fg(s):
    return {"CRITICAL": RED, "HIGH": ORANGE,
            "MEDIUM": YELLOW, "LOW": GREEN}.get(s, MUTED)

def sev_bg(s):
    return {"CRITICAL": RED_LT, "HIGH": ORANGE_LT,
            "MEDIUM": YELLOW_LT, "LOW": GREEN_LT}.get(s, OFF_WHITE)

def strip_prefix(n):
    """Remove internal graph prefixes for display."""
    return (n.replace("CAPABILITY::", "")
             .replace("ACTION::", "")
             .replace("iam:PassRole+", "PassRole+"))

def fmt_path(path):
    """Render a path list as a readable arrow chain."""
    return "  >>  ".join(strip_prefix(n) for n in path)


# ─────────────────────────────────────────────────────────────────────────────
# Style factory  (one function, no global dict that can break)
# ─────────────────────────────────────────────────────────────────────────────
def style(fontName="Helvetica", fontSize=9, textColor=TEXT,
          alignment=TA_LEFT, leading=None, spaceAfter=2, bold=False):
    fn = "Helvetica-Bold" if bold else fontName
    return ParagraphStyle(
        "_",
        fontName=fn,
        fontSize=fontSize,
        textColor=textColor,
        alignment=alignment,
        leading=leading or fontSize * 1.42,
        spaceAfter=spaceAfter,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Table helpers
# ─────────────────────────────────────────────────────────────────────────────
def th(text, align=TA_CENTER):
    """Table header cell."""
    return Paragraph(
        f"<b>{text}</b>",
        ParagraphStyle("_th", fontName="Helvetica-Bold", fontSize=8,
                       textColor=WHITE, alignment=align, leading=11),
    )

def td(text, fontSize=9, textColor=TEXT, alignment=TA_LEFT,
       bold=False, mono=False, leading=None):
    """Regular table data cell."""
    fn = "Courier" if mono else ("Helvetica-Bold" if bold else "Helvetica")
    return Paragraph(
        text,
        ParagraphStyle("_td", fontName=fn, fontSize=fontSize,
                       textColor=textColor, alignment=alignment,
                       leading=leading or fontSize * 1.38, spaceAfter=0),
    )

def striped_ts(n_data_rows, header_bg=NAVY, pad=6, lpad=8):
    """Striped table style with dark header."""
    ts = TableStyle([
        ("BACKGROUND",    (0, 0), (-1,  0), header_bg),
        ("GRID",          (0, 0), (-1, -1), 0.3,  BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), pad),
        ("BOTTOMPADDING", (0, 0), (-1, -1), pad),
        ("LEFTPADDING",   (0, 0), (-1, -1), lpad),
        ("RIGHTPADDING",  (0, 0), (-1, -1), lpad),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ])
    for i in range(1, n_data_rows + 1):
        ts.add("BACKGROUND", (0, i), (-1, i),
               OFF_WHITE if i % 2 == 0 else WHITE)
    return ts


# ─────────────────────────────────────────────────────────────────────────────
# Callout box (coloured bordered paragraph)
# ─────────────────────────────────────────────────────────────────────────────
def callout(text, bg=BLUE_LT, border=BLUE):
    return Table(
        [[Paragraph(text, style(fontSize=9.5, leading=16))]],
        colWidths=[CW],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), bg),
            ("BOX",           (0, 0), (-1, -1), 1.2, border),
            ("TOPPADDING",    (0, 0), (-1, -1), 11),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
            ("LEFTPADDING",   (0, 0), (-1, -1), 14),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 14),
            ("ROUNDEDCORNERS", [5]),
        ]),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Section heading (large title + blue rule + optional subtitle)
# ─────────────────────────────────────────────────────────────────────────────
def section_head(title, subtitle=None):
    els = [
        Spacer(1, 0.05 * cm),
        Paragraph(title,
                  style(fontSize=15, bold=True, textColor=NAVY,
                        leading=20, spaceAfter=3)),
        # 2 pt blue rule
        Table([[""]], colWidths=[CW],
              style=TableStyle([
                  ("BACKGROUND",    (0, 0), (-1, -1), BLUE),
                  ("TOPPADDING",    (0, 0), (-1, -1), 1.2),
                  ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                  ("LEFTPADDING",   (0, 0), (-1, -1), 0),
                  ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
              ])),
    ]
    if subtitle:
        els += [Spacer(1, 0.1 * cm),
                Paragraph(subtitle,
                          style(fontSize=9, textColor=TEXT_SOFT, leading=14))]
    els.append(Spacer(1, 0.22 * cm))
    return els


# ─────────────────────────────────────────────────────────────────────────────
# Page header / footer callbacks
# ─────────────────────────────────────────────────────────────────────────────
def _draw_page_header_footer(canvas, doc):
    canvas.saveState()

    # ── 5 pt accent bar at very top ──────────────────────────────────────────
    canvas.setFillColor(BLUE)
    canvas.rect(0, PH - 5, PW, 5, fill=1, stroke=0)

    # ── Header band (light grey) ─────────────────────────────────────────────
    canvas.setFillColor(OFF_WHITE)
    canvas.rect(0, PH - 30, PW, 25, fill=1, stroke=0)

    # Header bottom rule
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.4)
    canvas.line(LM, PH - 30, PW - RM, PH - 30)

    # Report name (left)
    canvas.setFillColor(NAVY)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(LM, PH - 21, "IAM RISK INTELLIGENCE REPORT")

    # Sub-label (middle)
    canvas.setFillColor(TEXT_SOFT)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(LM + 185, PH - 21, "Privilege Escalation Analysis")

    # Page number (right)
    canvas.setFillColor(BLUE)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawRightString(PW - RM, PH - 21, f"Page {doc.page}")

    # ── Footer rule ───────────────────────────────────────────────────────────
    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.4)
    canvas.line(LM, 24, PW - RM, 24)

    # Footer text
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(LM, 13,
                      "Confidential  |  IAM Defender  |  Internal Use Only")
    canvas.drawRightString(PW - RM, 13, GEN_D)

    canvas.restoreState()


def _draw_cover_footer(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(BLUE)
    canvas.rect(0, PH - 5, PW, 5, fill=1, stroke=0)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawCentredString(PW / 2, 13,
        f"Confidential  |  IAM Defender  |  {GEN_TS}")
    canvas.restoreState()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 1 — Cover
# ─────────────────────────────────────────────────────────────────────────────
def build_cover(findings, criticality, remediation, total_principals):
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

    els = []

    # ── Hero block ────────────────────────────────────────────────────────────
    hero_rows = [
        [Paragraph(
            "IAM Risk Intelligence Report",
            ParagraphStyle("_ht", fontName="Helvetica-Bold", fontSize=26,
                           textColor=WHITE, leading=32, spaceAfter=6))],
        [Paragraph(
            "Privilege Escalation and Attack Surface Analysis",
            ParagraphStyle("_hs", fontName="Helvetica", fontSize=12,
                           textColor=MUTED, leading=18, spaceAfter=4))],
        [Paragraph(
            f"Generated: {GEN_TS}",
            ParagraphStyle("_hd", fontName="Helvetica", fontSize=9,
                           textColor=MUTED, leading=14))],
    ]
    els.append(Table(
        hero_rows, colWidths=[CW],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), NAVY),
            ("LEFTPADDING",   (0, 0), (-1, -1), 24),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 24),
            ("TOPPADDING",    (0, 0), (-1, -1), 28),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 28),
            ("ROUNDEDCORNERS", [8]),
        ]),
    ))
    els.append(Spacer(1, 0.4 * cm))

    # ── 6 stat cards ─────────────────────────────────────────────────────────
    card_w = CW / 6

    def stat_card(value, label, val_color):
        return Table(
            [
                [Paragraph(str(value),
                           ParagraphStyle("_cv", fontName="Helvetica-Bold",
                                          fontSize=24, textColor=val_color,
                                          alignment=TA_CENTER, leading=28))],
                [Paragraph(label,
                           ParagraphStyle("_cl", fontName="Helvetica",
                                          fontSize=7.5, textColor=MUTED,
                                          alignment=TA_CENTER, leading=11))],
            ],
            colWidths=[card_w - 0.2 * cm],
            style=TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), WHITE),
                ("BOX",           (0, 0), (-1, -1), 0.5, BORDER),
                ("TOPPADDING",    (0, 0), (-1, -1), 13),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 13),
                ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
                ("ROUNDEDCORNERS", [6]),
            ]),
        )

    els.append(Table(
        [[
            stat_card(total_principals, "Principals Scanned", BLUE),
            stat_card(total_f,          "Total Findings",     TEXT),
            stat_card(critical,         "Critical",           RED),
            stat_card(high,             "High",               ORANGE),
            stat_card(medium,           "Medium",             YELLOW),
            stat_card(low,              "Low",                GREEN),
        ]],
        colWidths=[card_w] * 6,
        style=TableStyle([
            ("LEFTPADDING",  (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ]),
    ))
    els.append(Spacer(1, 0.35 * cm))

    # ── Severity bar ─────────────────────────────────────────────────────────
    sev_text = (
        '<font color="#ef4444"><b>CRITICAL: ' + str(critical) + '</b></font>'
        '&nbsp;&nbsp;&nbsp;'
        '<font color="#f97316"><b>HIGH: ' + str(high) + '</b></font>'
        '&nbsp;&nbsp;&nbsp;'
        '<font color="#eab308"><b>MEDIUM: ' + str(medium) + '</b></font>'
        '&nbsp;&nbsp;&nbsp;'
        '<font color="#22c55e"><b>LOW: ' + str(low) + '</b></font>'
    )
    els.append(Table(
        [[
            Paragraph("<b>Severity Distribution</b>",
                      style(fontSize=8.5, bold=True)),
            Paragraph(sev_text,
                      ParagraphStyle("_sb", fontName="Helvetica", fontSize=9,
                                     textColor=TEXT, alignment=TA_RIGHT,
                                     leading=14)),
        ]],
        colWidths=[CW * 0.28, CW * 0.72],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), OFF_WHITE),
            ("BOX",           (0, 0), (-1, -1), 0.5, BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING",   (0, 0), (-1, -1), 12),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ROUNDEDCORNERS", [5]),
        ]),
    ))
    els.append(Spacer(1, 0.35 * cm))

    # ── Cross-account alert ───────────────────────────────────────────────────
    if cross > 0:
        els.append(callout(
            f'<font color="#b91c1c"><b>Warning: {cross} Cross-Account '
            f'Escalation{"s" if cross > 1 else ""} Detected</b></font>  '
            '<font color="#475569">These paths traverse AWS account boundaries '
            'and significantly expand blast radius. Prioritise immediately.'
            '</font>',
            bg=RED_LT, border=RED,
        ))
        els.append(Spacer(1, 0.3 * cm))

    # ── Scope summary table ───────────────────────────────────────────────────
    scope_data = [
        [th("Metric", TA_LEFT),            th("Value", TA_LEFT)],
        [td("Total Principals Scanned",    bold=True),
         td(str(total_principals),         bold=True, textColor=BLUE)],
        [td("Principals with Escalation Paths", bold=True),
         td(str(affected),                 bold=True, textColor=BLUE)],
        [td("Total Escalation Paths",      bold=True),
         td(str(total_f),                  bold=True, textColor=BLUE)],
        [td("Critical / High Findings",    bold=True),
         td(f"{critical} / {high}",        bold=True,
            textColor=RED if critical else ORANGE)],
        [td("Most Prevalent Attack Pattern", bold=True),
         td(top_pat,                        textColor=TEXT_SOFT)],
        [td("Cross-Account Escalation Paths", bold=True),
         td(str(cross),                    bold=True,
            textColor=RED if cross else GREEN)],
        [td("Minimal Remediation Actions", bold=True),
         td(str(n_fixes),                  bold=True, textColor=ORANGE)],
    ]
    els.append(Table(
        scope_data,
        colWidths=[CW * 0.62, CW * 0.38],
        style=striped_ts(len(scope_data) - 1),
    ))

    els.append(PageBreak())
    return els


# ─────────────────────────────────────────────────────────────────────────────
# PAGE 2 — Executive Summary
# ─────────────────────────────────────────────────────────────────────────────
def build_exec_summary(findings, criticality):
    els = []
    els += section_head("Executive Summary")

    critical  = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    total     = len(findings)
    affected  = len(set(f.get("principal", "") for f in findings))
    patterns  = Counter(f.get("pattern", "") for f in findings)
    top_pat   = (patterns.most_common(1)[0][0].replace("_", " ")
                 if patterns else "N/A")

    els.append(callout(
        f"This report identifies <b>{total} privilege escalation "
        f"path{'s' if total != 1 else ''}</b> across "
        f"<b>{affected} IAM principal{'s' if affected != 1 else ''}</b>. "
        f"<b>{critical}</b> finding{'s are' if critical != 1 else ' is'} rated "
        f'<font color="#ef4444"><b>CRITICAL</b></font> and require immediate '
        f"remediation. The most prevalent attack technique is <b>{top_pat}</b>.",
    ))
    els.append(Spacer(1, 0.45 * cm))

    # ── Top 10 Critical Nodes ─────────────────────────────────────────────────
    els.append(Paragraph(
        "Top 10 Critical Nodes",
        style(fontSize=11, bold=True, textColor=BLUE, leading=16)))
    els.append(Paragraph(
        "Ranked by structural criticality — frequency of appearance across "
        "escalation paths, weighted by risk score.",
        style(fontSize=9, textColor=TEXT_SOFT, leading=14)))
    els.append(Spacer(1, 0.12 * cm))

    top_nodes = list(criticality.items())[:10]
    node_rows = [
        [th("#"), th("Node Name", TA_LEFT), th("Type"), th("Criticality Score")]
    ]
    for rank, (node, score) in enumerate(top_nodes, 1):
        if "CAPABILITY::" in node:
            ntype, nc = "Capability", GREEN
        elif "ACTION::" in node:
            ntype, nc = "Action",     PURPLE
        else:
            ntype, nc = "Principal",  BLUE
        node_rows.append([
            td(str(rank), alignment=TA_CENTER, textColor=MUTED, bold=True),
            td(strip_prefix(node)),
            td(ntype, alignment=TA_CENTER, fontSize=8, textColor=nc),
            td(f"<b>{score:.1f}</b>", alignment=TA_CENTER,
               fontSize=11, textColor=BLUE, bold=True),
        ])
    els.append(Table(
        node_rows,
        colWidths=[1.3 * cm, 9.5 * cm, 2.4 * cm, 3.1 * cm],
        style=striped_ts(len(node_rows) - 1),
        repeatRows=1,
    ))
    els.append(Spacer(1, 0.45 * cm))

    # ── Attack Pattern Breakdown ──────────────────────────────────────────────
    els.append(Paragraph(
        "Attack Pattern Breakdown",
        style(fontSize=11, bold=True, textColor=BLUE, leading=16)))
    els.append(Paragraph(
        "Distribution of detected MITRE ATT&amp;CK-aligned attack techniques.",
        style(fontSize=9, textColor=TEXT_SOFT, leading=14)))
    els.append(Spacer(1, 0.12 * cm))

    MITRE_MAP = {
        "PASSROLE_COMPUTE_EXECUTION":  "T1098 - Account Manipulation",
        "POLICY_MANIPULATION":         "T1098 - Account Manipulation",
        "PRIVILEGE_AMPLIFICATION":     "T1078 - Valid Accounts",
        "CROSS_ACCOUNT_PIVOT":         "T1021 - Remote Services",
        "MULTI_HOP_LATERAL_MOVEMENT":  "T1021 - Remote Services",
        "ROLE_ASSUMPTION_ABUSE":       "T1078 - Valid Accounts",
        "IDENTITY_CREATION_ABUSE":     "T1136 - Create Account",
        "PERSISTENCE_VIA_ACCESS_KEY":  "T1098.001 - Additional Cloud Credentials",
        "GENERIC_ESCALATION":          "T1078 - Valid Accounts",
    }
    pat_rows = [
        [th("Attack Pattern", TA_LEFT), th("Count"),
         th("Share"), th("MITRE ATT&amp;CK Technique", TA_LEFT)]
    ]
    for pat, cnt in patterns.most_common():
        pat_rows.append([
            td(pat.replace("_", " ")),
            td(str(cnt), alignment=TA_CENTER, fontSize=11,
               bold=True, textColor=BLUE),
            td(f"{cnt / total * 100:.0f}%",
               alignment=TA_CENTER, fontSize=9, textColor=TEXT_SOFT),
            td(MITRE_MAP.get(pat, "T1078 - Valid Accounts"),
               fontSize=8, textColor=TEXT_SOFT),
        ])
    els.append(Table(
        pat_rows,
        colWidths=[5.8 * cm, 1.5 * cm, 1.5 * cm, 7.5 * cm],
        style=striped_ts(len(pat_rows) - 1),
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
    els.append(Spacer(1, 0.4 * cm))

    # ── Structural choke points ───────────────────────────────────────────────
    if dominators:
        els.append(Paragraph(
            "Structural Choke Points (Dominators)",
            style(fontSize=11, bold=True, textColor=BLUE, leading=16)))
        els.append(Paragraph(
            "These nodes appear in every escalation path. "
            "Remediating them blocks all paths simultaneously.",
            style(fontSize=9, textColor=TEXT_SOFT, leading=14)))
        els.append(Spacer(1, 0.12 * cm))

        DOM_REC = {
            "sts:AssumeRole": "Restrict the downstream role trust policy to deny this principal",
            "iam:PassRole":   "Limit iam:PassRole to specific approved role ARNs only",
        }
        dom_rows = [
            [th("#"), th("Choke Point Node", TA_LEFT),
             th("Type"), th("Recommended Action", TA_LEFT)]
        ]
        for i, d in enumerate(dominators, 1):
            ntype = ("Capability" if "CAPABILITY" in d
                     else "Action" if "ACTION" in d else "Principal")
            rec = next((v for k, v in DOM_REC.items() if k in d),
                       "Remove or restrict this permission or trust relationship")
            dom_rows.append([
                td(str(i), alignment=TA_CENTER, textColor=MUTED, bold=True),
                td(strip_prefix(d), mono=True, fontSize=8),
                td(ntype, alignment=TA_CENTER, fontSize=8, textColor=TEXT_SOFT),
                td(rec, fontSize=8, textColor=TEXT_SOFT),
            ])
        els.append(Table(
            dom_rows,
            colWidths=[0.9 * cm, 5.5 * cm, 2.0 * cm, 7.9 * cm],
            style=striped_ts(len(dom_rows) - 1),
            repeatRows=1,
        ))
        els.append(Spacer(1, 0.45 * cm))

    # ── Ordered fix set ───────────────────────────────────────────────────────
    els.append(Paragraph(
        "Ordered Minimal Fix Set",
        style(fontSize=11, bold=True, textColor=BLUE, leading=16)))
    els.append(Paragraph(
        "Each entry removes one edge from the attack graph, "
        "covering all escalation paths with the fewest IAM changes.",
        style(fontSize=9, textColor=TEXT_SOFT, leading=14)))
    els.append(Spacer(1, 0.12 * cm))

    def action_for(src, dst):
        s, d = src.lower(), dst.lower()
        if "passrole" in s or "passrole" in d:
            return "Restrict iam:PassRole to specific approved role ARNs"
        if "assumerole" in s or "assumerole" in d:
            return "Tighten role trust policy — remove unnecessary principals"
        if "attachrolepolicy" in d or "putrolepolicy" in d:
            return "Remove IAM policy modification permissions from this role"
        if "createaccesskey" in d:
            return "Remove iam:CreateAccessKey from this principal"
        if "createloginprofile" in d:
            return "Remove iam:CreateLoginProfile permission"
        if "full_admin" in d or "administratoraccess" in d:
            return "Detach AdministratorAccess managed policy"
        if "privilege_propagation" in d:
            return "Remove wildcard IAM permission (iam:* or *)"
        return "Remove or restrict this IAM permission edge"

    fix_rows = [
        [th("#"), th("Source Node", TA_LEFT),
         th("Target Node", TA_LEFT), th("Action Required", TA_LEFT)]
    ]
    for i, fix in enumerate(fixes, 1):
        if isinstance(fix, (list, tuple)) and len(fix) == 2:
            src, dst = str(fix[0]), str(fix[1])
        elif isinstance(fix, str) and " -> " in fix:
            src, dst = fix.split(" -> ", 1)
        else:
            src, dst = str(fix), ""
        fix_rows.append([
            td(str(i), alignment=TA_CENTER, textColor=MUTED, bold=True),
            td(strip_prefix(src), mono=True, fontSize=7.5),
            td(strip_prefix(dst), mono=True, fontSize=7.5),
            td(action_for(src, dst), fontSize=8, textColor=TEXT_SOFT),
        ])
    els.append(Table(
        fix_rows,
        colWidths=[0.8 * cm, 4.5 * cm, 4.5 * cm, 6.5 * cm],
        style=striped_ts(len(fix_rows) - 1),
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
        "All Escalation Findings",
        f"Complete list of {len(findings)} detected privilege escalation paths, "
        "sorted by risk score (highest first).",
    )

    sorted_f = sorted(findings, key=lambda f: f.get("risk", 0), reverse=True)

    # Column widths (must sum to CW ~= 451 pt)
    # #   | Principal | Capability | Severity | Risk | Pattern | Path
    col_w = [0.65*cm, 2.9*cm, 2.6*cm, 1.75*cm, 0.9*cm, 2.9*cm, 4.6*cm]

    rows = [[
        th("#"),
        th("Principal",       TA_LEFT),
        th("Capability",      TA_LEFT),
        th("Severity"),
        th("Risk"),
        th("Pattern",         TA_LEFT),
        th("Escalation Path", TA_LEFT),
    ]]

    ts = TableStyle([
        ("BACKGROUND",    (0, 0), (-1,  0), NAVY),
        ("GRID",          (0, 0), (-1, -1), 0.25, BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ])

    for i, f in enumerate(sorted_f, 1):
        sev   = f.get("severity", "")
        fg    = sev_fg(sev)
        bg    = sev_bg(sev)
        risk  = f.get("risk", 0)
        pat   = f.get("pattern", "").replace("_", " ")
        path  = fmt_path(f.get("path", []))
        row_bg = OFF_WHITE if i % 2 == 0 else WHITE

        rows.append([
            Paragraph(str(i), ParagraphStyle("_rn", fontName="Helvetica",
                fontSize=8, textColor=MUTED, alignment=TA_CENTER,
                leading=11, wordWrap=None)),
            td(f.get("principal", ""), bold=True, fontSize=8,
               textColor=TEXT, leading=12),
            td(f.get("capability", "").replace("_", " "),
               fontSize=7.5, textColor=TEXT_SOFT, leading=11),
            Paragraph(sev, ParagraphStyle(
                "_sev", fontName="Helvetica-Bold", fontSize=7.5,
                textColor=fg, alignment=TA_CENTER, leading=11,
                backColor=bg, borderPadding=2)),
            td(f"<b>{risk:.0f}</b>", alignment=TA_CENTER,
               fontSize=10, bold=True, textColor=fg),
            td(pat, fontSize=7, textColor=TEXT_SOFT, leading=10),
            td(path, mono=True, fontSize=6.5,
               textColor=TEXT_SOFT, leading=9.5),
        ])
        ts.add("BACKGROUND", (0, i), (-1, i), row_bg)

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
    story += build_cover(findings, criticality, remediation, total_principals)
    story += build_exec_summary(findings, criticality)
    story += build_remediation(remediation)
    story += build_findings(findings)

    # End-of-report footer note
    story.append(Spacer(1, 0.4 * cm))
    story.append(Table(
        [[""]],
        colWidths=[CW],
        style=TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 0.6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]),
    ))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(
        f"End of Report  |  IAM Defender  |  {GEN_TS}",
        style(fontSize=7.5, textColor=MUTED, alignment=TA_CENTER),
    ))

    doc.build(
        story,
        onFirstPage=_draw_cover_footer,
        onLaterPages=_draw_page_header_footer,
    )
    return buf.getvalue()