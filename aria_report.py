import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, Arc, FancyArrowPatch
import matplotlib.patheffects as pe
import numpy as np
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 Table as _OrigTable,
                                 TableStyle, Image, PageBreak, HRFlowable,
                                 KeepTogether)
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus.flowables import Flowable
import io
import os

def Table(data, *args, **kwargs):
    """Safe Table wrapper — returns empty Spacer if data is empty."""
    if not data or (isinstance(data, list) and len(data) == 0):
        return Spacer(1, 0)
    return _OrigTable(data, *args, **kwargs)

# ── Color palette — Black & White ─────────────────────────────────────────────
BG_DARK      = colors.white
BG_MID       = colors.HexColor('#f1f1f1')
BG_CARD      = colors.HexColor('#f8f8f8')
ACCENT_RED   = colors.HexColor('#cc0000')
ACCENT_ORG   = colors.HexColor('#cc0000')
ACCENT_YLW   = colors.HexColor('#555555')
ACCENT_GRN   = colors.HexColor('#222222')
ACCENT_CYAN  = colors.HexColor('#333333')
ACCENT_BLUE  = colors.HexColor('#333333')
ACCENT_PURP  = colors.HexColor('#444444')
TEXT_WHITE   = colors.black
TEXT_GREY    = colors.HexColor('#555555')
TEXT_LGREY   = colors.HexColor('#222222')
BORDER_DIM   = colors.HexColor('#cccccc')
BORDER_GLOW  = colors.HexColor('#cc000022')
ROW_ALT      = colors.HexColor('#eeeeee')

W, H = letter

# ── Helper: matplotlib fig → ReportLab Image ──────────────────────────────────
def fig_to_rl(fig, w_inch, h_inch):
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=300, bbox_inches='tight',
                facecolor='white')
    plt.close(fig)
    buf.seek(0)
    return Image(buf, width=w_inch*inch, height=h_inch*inch)

# ── Threat gauge (semicircle) ──────────────────────────────────────────────────
def make_gauge(score=92):
    fig, ax = plt.subplots(figsize=(5, 2.8), facecolor='white')
    ax.set_xlim(-1.3, 1.3); ax.set_ylim(-0.3, 1.3); ax.axis('off')

    # Background arc
    theta = np.linspace(np.pi, 0, 300)
    r = 1.0
    ax.plot(r*np.cos(theta), r*np.sin(theta), color='#cccccc', lw=18, solid_capstyle='round')

    # Color segments (greyscale)
    segs = [(0,33,'#aaaaaa'),(33,66,'#888888'),(66,85,'#555555'),(85,100,'#cc0000')]
    for s,e,c in segs:
        t = np.linspace(np.pi - s/100*np.pi, np.pi - e/100*np.pi, 100)
        ax.plot(r*np.cos(t), r*np.sin(t), color=c, lw=18, solid_capstyle='butt', alpha=0.35)

    # Active fill up to score
    t_fill = np.linspace(np.pi, np.pi - score/100*np.pi, 300)
    ax.plot(r*np.cos(t_fill), r*np.sin(t_fill), color='#cc0000', lw=18,
            solid_capstyle='round', alpha=0.9)

    # Needle
    angle = np.pi - score/100*np.pi
    ax.annotate('', xy=(0.78*np.cos(angle), 0.78*np.sin(angle)),
                xytext=(0,0),
                arrowprops=dict(arrowstyle='->', color='black', lw=2.5,
                                mutation_scale=18))
    ax.plot(0, 0, 'o', color='black', ms=8, zorder=10)

    ax.text(0, 0.35, f'{score}', ha='center', va='center',
            fontsize=38, fontweight='bold', color='black', fontfamily='monospace')
    ax.text(0, 0.10, 'THREAT SCORE', ha='center', va='center',
            fontsize=7, color='#555555', fontfamily='monospace', fontweight='bold')

    for label, x, y in [('LOW',-1.15,0.05),('MED',-0.05,1.15),('HIGH',1.05,0.05)]:
        ax.text(x, y, label, ha='center', fontsize=6.5, color='#888888',
                fontfamily='monospace', fontweight='bold')

    fig.tight_layout(pad=0)
    return fig

# ── Capability radar — fully dynamic ──────────────────────────────────────────
def make_radar(caps=None, vals=None):
    if caps is None:
        caps = []
    if vals is None:
        vals = []

    # Only include axes where score > 0
    active = [(c, v) for c, v in zip(caps, vals) if v > 0]
    if len(active) < 3:
        # Fallback if too few — pad with zero axes
        while len(active) < 3:
            active.append(('N/A', 0))
    cats = [c for c, _ in active]
    vals = [v for _, v in active]
    N = len(cats)

    # Scale figure height with number of axes so labels don't crowd
    fig_size = max(3.0, min(4.5, 2.5 + N * 0.2))
    fig, ax = plt.subplots(figsize=(fig_size, fig_size),
                            subplot_kw=dict(polar=True), facecolor='white')
    ax.set_facecolor('white')
    ax.set_theta_offset(np.pi/2); ax.set_theta_direction(-1)

    angles = [n/N*2*np.pi for n in range(N)]
    angles += angles[:1]
    vals_plot = vals + vals[:1]

    for r in [2,4,6,8,10]:
        ring = [r]*N + [r]
        ax.plot(angles, ring, color='#cccccc', lw=0.8)

    ax.plot(angles, vals_plot, color='#cc0000', lw=2, zorder=5)
    ax.fill(angles, vals_plot, alpha=0.15, color='#cc0000')

    # Label font scales down if many axes
    label_fs = max(5.5, 8.5 - N * 0.25)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(cats, color='#333333', fontsize=label_fs, fontfamily='monospace')
    ax.set_ylim(0,10); ax.set_yticks([])
    ax.spines['polar'].set_color('#cccccc')
    ax.grid(False)
    fig.tight_layout(pad=0.4)
    return fig, fig_size

# ── Section entropy bar chart ──────────────────────────────────────────────────
def make_entropy_chart(sections=None, entropies=None):
    if not sections or not entropies:
        sections = ['NO DATA']; entropies = [0.0]

    fig, ax = plt.subplots(figsize=(6.5, 2.8), facecolor='white')
    ax.set_facecolor('white')

    bar_colors = []
    for e in entropies:
        if e >= 7.0:   bar_colors.append('#cc0000')
        elif e >= 6.0: bar_colors.append('#555555')
        elif e >= 5.0: bar_colors.append('#888888')
        else:          bar_colors.append('#aaaaaa')

    bars = ax.barh(sections, entropies, color=bar_colors, height=0.6,
                   edgecolor='none', alpha=0.85)

    ax.axvline(6.0, color='#cc0000', lw=1.2, linestyle='--', alpha=0.7)
    ax.axvline(7.0, color='#cc0000', lw=1.2, linestyle=':', alpha=0.5)
    ax.text(6.02, len(sections)-0.3, 'suspicious', color='#cc0000',
            fontsize=6.5, fontfamily='monospace')

    for bar, val in zip(bars, entropies):
        ax.text(val + 0.05, bar.get_y() + bar.get_height()/2,
                f'{val:.2f}', va='center', color='#222222',
                fontsize=7, fontfamily='monospace')

    ax.set_xlim(0, 8.5)
    ax.set_xlabel('Entropy', color='#555555', fontsize=8, fontfamily='monospace')
    ax.tick_params(colors='#333333', labelsize=7.5)
    for spine in ax.spines.values(): spine.set_color('#cccccc')
    plt.setp(ax.get_yticklabels(), fontfamily='monospace', color='#333333')
    fig.tight_layout(pad=0.4)
    return fig

# ── Detection breakdown donut ──────────────────────────────────────────────────
def make_detection_donut(vt_malicious=0, vt_suspicious=0, vt_total=0):
    fig, ax = plt.subplots(figsize=(3.2, 3.2), facecolor='white')
    ax.set_facecolor('white')

    if vt_total > 0:
        vt_clean = max(0, vt_total - vt_malicious - vt_suspicious)
        sizes, wedge_colors = [], []
        if vt_malicious > 0:
            sizes.append(vt_malicious); wedge_colors.append('#cc0000')
        if vt_suspicious > 0:
            sizes.append(vt_suspicious); wedge_colors.append('#ff8800')
        if vt_clean > 0:
            sizes.append(vt_clean); wedge_colors.append('#aaaaaa')
        if not sizes:
            sizes = [1]; wedge_colors = ['#aaaaaa']
        label_str = f'{vt_malicious}/{vt_total}'
        sub2_str  = f'{vt_suspicious} SUSPICIOUS' if vt_suspicious else ('ALL CLEAN' if vt_malicious == 0 else '')
        sub2_col  = '#cc0000' if vt_malicious > 0 else '#22aa55'
    else:
        sizes = [100]; wedge_colors = ['#aaaaaa']
        label_str = '0/0'
        sub2_str  = 'NOT IN VT'
        sub2_col  = '#888888'

    wedges, _ = ax.pie(sizes, colors=wedge_colors, startangle=90,
                        wedgeprops=dict(width=0.45, edgecolor='white', linewidth=2))

    ax.text(0, 0.1, label_str, ha='center', va='center',
            fontsize=22, fontweight='bold', color='black', fontfamily='monospace')
    ax.text(0, -0.2, 'VT DETECTION', ha='center', va='center',
            fontsize=6.5, color='#555555', fontfamily='monospace', fontweight='bold')
    ax.text(0, -0.42, sub2_str, ha='center', va='center',
            fontsize=6, color=sub2_col, fontfamily='monospace', fontweight='bold')

    fig.tight_layout(pad=0)
    return fig

# ── Confidence bar ─────────────────────────────────────────────────────────────
def make_confidence_bar(pct=92):
    fig, ax = plt.subplots(figsize=(5.5, 0.7), facecolor='white')
    ax.set_xlim(0,100); ax.set_ylim(0,1); ax.axis('off')
    ax.barh(0.5, 100, height=0.55, color='#dddddd', left=0)
    ax.barh(0.5, pct, height=0.55, color='#cc0000', left=0, alpha=0.85)
    ax.text(pct/2, 0.5, f'{pct}% CONFIDENCE — HIGH', ha='center', va='center',
            color='white', fontsize=9, fontweight='bold', fontfamily='monospace')
    fig.tight_layout(pad=0)
    return fig

# ── Capability matrix chart ────────────────────────────────────────────────────
def make_capability_matrix(capabilities=None):
    # capabilities: list of (name, status) tuples, status in CONFIRMED/LIKELY/POSSIBLE/UNKNOWN
    if not capabilities:
        capabilities = [('No significant capabilities detected', 'UNKNOWN')]

    status_colors = {'CONFIRMED': '#cc0000', 'LIKELY': '#555555', 'POSSIBLE': '#888888', 'UNKNOWN': '#aaaaaa'}

    fig_h = max(1.5, len(capabilities) * 0.38 + 0.4)
    fig, ax = plt.subplots(figsize=(6.5, fig_h), facecolor='white')
    ax.set_facecolor('white')
    ax.axis('off')

    for i, entry in enumerate(capabilities):
        cap, status = entry[0], entry[1]
        col = status_colors.get(status, '#888888')
        y = len(capabilities) - i - 1
        bg_col = '#f8f8f8' if i % 2 == 0 else '#eeeeee'
        ax.barh(y, 10, height=0.85, left=0, color=bg_col, zorder=1)
        ax.barh(y, 1.8, height=0.6, left=0.1, color=col, alpha=0.15, zorder=2)
        ax.text(1.0, y, status, ha='center', va='center',
                color=col, fontsize=7, fontweight='bold', fontfamily='monospace', zorder=3)
        ax.plot(0.05, y, 'o', color=col, ms=5, zorder=4)
        ax.text(2.2, y, cap, va='center', color='#222222',
                fontsize=8, fontfamily='monospace', zorder=3)

    ax.set_xlim(0, 10); ax.set_ylim(-0.5, len(capabilities) - 0.5)
    fig.tight_layout(pad=0.3)
    return fig, fig_h

# ── Kill Chain diagram ─────────────────────────────────────────────────────────
def make_kill_chain(steps=None):
    fig, ax = plt.subplots(figsize=(7.0, 2.4), facecolor='white')
    ax.set_xlim(0, 10); ax.set_ylim(0, 3); ax.axis('off')
    ax.set_facecolor('white')

    if steps is None:
        steps = [
            ('DELIVERY',     'Malicious\nfile dropped',   '1'),
            ('EXECUTION',    'Code runs\non system',      '2'),
            ('PERSISTENCE',  'Survives\nreboot',          '3'),
            ('COLLECTION',   'Data\ncaptured',            '4'),
            ('EXFILTRATION', 'Data sent\nto attacker',    '5'),
        ]
    # Normalize to (title, desc, num) triples
    steps = [(s[0], s[1], str(i+1)) for i, s in enumerate(steps)]

    n_steps = len(steps)
    total_w = 9.8
    gap = 0.18
    box_w = (total_w - gap * (n_steps - 1)) / n_steps
    box_h = 1.6
    start_x = 0.10

    for i, (title, desc, num) in enumerate(steps):
        x = start_x + i * (box_w + gap)
        y = 0.55

        fc = '#fff0f0' if i == len(steps)-1 else '#f8f8f8'
        ec = '#cc0000' if i == len(steps)-1 else '#cccccc'
        lw = 1.5 if i == len(steps)-1 else 0.8
        rect = plt.Rectangle((x, y), box_w, box_h, facecolor=fc,
                               edgecolor=ec, linewidth=lw, zorder=3)
        ax.add_patch(rect)

        # Step number badge
        circle = plt.Circle((x + 0.17, y + box_h - 0.17), 0.13,
                              color='#cc0000', zorder=4)
        ax.add_patch(circle)
        ax.text(x + 0.17, y + box_h - 0.17, num, ha='center', va='center',
                fontsize=6.5, fontweight='bold', color='white',
                fontfamily='monospace', zorder=5)

        # Title — inside box, below badge
        ax.text(x + box_w/2, y + box_h - 0.48, title, ha='center', va='center',
                fontsize=6.5, fontweight='bold',
                color='#cc0000' if i == len(steps)-1 else '#222222',
                fontfamily='monospace', zorder=4)

        # Divider line
        ax.plot([x + 0.1, x + box_w - 0.1], [y + box_h - 0.7, y + box_h - 0.7],
                color='#dddddd', lw=0.6, zorder=3)

        # Description — bottom half of box
        ax.text(x + box_w/2, y + 0.44, desc, ha='center', va='center',
                fontsize=5.8, color='#555555', fontfamily='monospace',
                multialignment='center', zorder=4)

        # Arrow to next
        if i < len(steps) - 1:
            ax.annotate('', xy=(x + box_w + gap, y + box_h/2),
                        xytext=(x + box_w, y + box_h/2),
                        arrowprops=dict(arrowstyle='->', color='#999999',
                                        lw=1.0, mutation_scale=10), zorder=2)

    fig.tight_layout(pad=0.2)
    return fig

# ── Risk Matrix ────────────────────────────────────────────────────────────────
def make_risk_matrix(likelihood='HIGH', impact='HIGH'):
    fig, ax = plt.subplots(figsize=(3.5, 3.0), facecolor='white')
    ax.set_facecolor('white')
    ax.set_xlim(0, 3); ax.set_ylim(0, 3)

    # Quadrant fills
    quads = [
        (0, 1, 1, 1, '#f8f8f8'),  # Low-Low
        (1, 1, 1, 1, '#f0f0f0'),  # High-Low
        (0, 0, 1, 1, '#f0f0f0'),  # Low-High
        (1, 0, 1, 1, '#fff0f0'),  # High-High
    ]
    for x, y, w, h, c in quads:
        ax.add_patch(plt.Rectangle((x*1.5, y*1.5), w*1.5, h*1.5,
                                    facecolor=c, edgecolor='#cccccc', lw=0.8))

    # Quadrant labels
    ax.text(0.75, 2.25, 'LOW RISK', ha='center', va='center',
            fontsize=7, color='#aaaaaa', fontfamily='monospace', fontweight='bold')
    ax.text(2.25, 2.25, 'MEDIUM RISK', ha='center', va='center',
            fontsize=7, color='#888888', fontfamily='monospace', fontweight='bold')
    ax.text(0.75, 0.75, 'MEDIUM RISK', ha='center', va='center',
            fontsize=7, color='#888888', fontfamily='monospace', fontweight='bold')
    ax.text(2.25, 0.75, 'CRITICAL RISK', ha='center', va='center',
            fontsize=7.5, color='#cc0000', fontfamily='monospace', fontweight='bold')

    # Plot this threat — position derived from computed likelihood/impact
    _star_x = 2.6 if likelihood in ('VERY HIGH', 'HIGH') else 0.75
    _star_y = 0.6 if impact in ('CATASTROPHIC', 'CRITICAL', 'HIGH') else 2.25
    ax.plot(_star_x, _star_y, '*', color='#cc0000', ms=18, zorder=5,
            markeredgecolor='#aa0000', markeredgewidth=0.5)
    ax.text(_star_x, _star_y - 0.32, 'THIS THREAT', ha='center', fontsize=6,
            color='#cc0000', fontfamily='monospace', fontweight='bold')

    # Axis labels
    ax.set_xticks([0.75, 2.25])
    ax.set_xticklabels(['LOW\nLIKELIHOOD', 'HIGH\nLIKELIHOOD'],
                        fontsize=7, fontfamily='monospace', color='#333333')
    ax.set_yticks([0.75, 2.25])
    ax.set_yticklabels(['HIGH\nIMPACT', 'LOW\nIMPACT'],
                        fontsize=7, fontfamily='monospace', color='#333333')
    ax.tick_params(length=0)

    for spine in ax.spines.values():
        spine.set_color('#cccccc')
        spine.set_linewidth(0.5)

    ax.set_title('RISK MATRIX', fontsize=8, fontfamily='monospace',
                  fontweight='bold', color='#333333', pad=6)
    fig.tight_layout(pad=0.4)
    return fig

# ── Remediation Roadmap ────────────────────────────────────────────────────────
def make_remediation_roadmap():
    fig, ax = plt.subplots(figsize=(7.0, 3.2), facecolor='white')
    ax.set_xlim(0, 10); ax.set_ylim(0, 4); ax.axis('off')
    ax.set_facecolor('white')

    lanes = [
        ('IMMEDIATE\n0–24 HOURS', '#cc0000', [
            'Isolate systems from network',
            'Preserve memory & disk images',
            'Block C2 domains at firewall',
            'Preserve memory & forensic imgs',
            'Reset exposed credentials',
        ]),
        ('SHORT TERM\n1–7 DAYS', '#555555', [
            'Scan org-wide for file hash',
            'Hunt suspicious file paths',
            'Audit registry Run keys fleet',
            'Notify insurer & legal counsel',
            'Submit sample to Any.run',
        ]),
        ('LONG TERM\n30+ DAYS', '#888888', [
            'Deploy EDR behavioral detection',
            'Email attachment sandboxing',
            'MFA rollout critical accounts',
            'Phishing awareness training',
            'RAT TTP threat hunt playbook',
        ]),
    ]

    col_w = 3.1
    for i, (header, col, items) in enumerate(lanes):
        x = 0.15 + i * (col_w + 0.15)
        # Header bar
        ax.add_patch(plt.Rectangle((x, 2.85), col_w, 0.85,
                                    facecolor=col, edgecolor='none'))
        ax.text(x + col_w/2, 3.28, header, ha='center', va='center',
                fontsize=7.5, fontweight='bold', color='white',
                fontfamily='monospace', multialignment='center')

        # Items box
        ax.add_patch(plt.Rectangle((x, 0.1), col_w, 2.72,
                                    facecolor='#f8f8f8' if i==0 else '#fafafa',
                                    edgecolor='#cccccc', lw=0.8))

        for j, item in enumerate(items):
            y = 2.55 - j * 0.48
            # Bullet dot
            dot_col = col
            ax.plot(x + 0.18, y, 'o', color=dot_col, ms=4, zorder=3)
            ax.text(x + 0.32, y, item, va='center', fontsize=6.8,
                    color='#222222', fontfamily='monospace')

    fig.tight_layout(pad=0.2)
    return fig

# ── String categorization chart ───────────────────────────────────────────────
def make_string_categories():
    cats = ['Network/C2', 'Crypto/Encrypt', 'Anti-Debug', 'File System', 'Registry', 'Injection', 'Keylog/Clip', 'Persistence']
    counts = [18, 24, 12, 15, 8, 14, 11, 9]
    colors_list = ['#cc0000','#555555','#888888','#444444','#666666','#333333','#777777','#999999']

    fig, ax = plt.subplots(figsize=(6.5, 2.6), facecolor='white')
    ax.set_facecolor('white')
    bars = ax.bar(cats, counts, color=colors_list, edgecolor='white', linewidth=0.5, width=0.65)
    for bar, val in zip(bars, counts):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                str(val), ha='center', va='bottom', fontsize=7.5,
                fontfamily='monospace', color='#222222', fontweight='bold')
    ax.set_ylabel('Analyst Strings', fontsize=7.5, color='#555555', fontfamily='monospace')
    ax.set_ylim(0, 30)
    ax.tick_params(axis='x', labelsize=6.8, colors='#333333')
    ax.tick_params(axis='y', labelsize=7, colors='#555555')
    plt.setp(ax.get_xticklabels(), fontfamily='monospace', rotation=15, ha='right')
    for spine in ax.spines.values(): spine.set_color('#cccccc')
    ax.yaxis.grid(True, color='#eeeeee', lw=0.5)
    ax.set_axisbelow(True)
    fig.tight_layout(pad=0.4)
    return fig

# ── Anomaly table (Expected vs Found) ─────────────────────────────────────────
def make_anomaly_visual(rows=None):
    if rows is None:
        rows = [
            ('Compile Timestamp', 'Past date, realistic',    'Not analyzed',               'UNKNOWN',   '#888888'),
            ('Rich Header',       'Present (MSVC builds)',   'Not extracted',               'UNKNOWN',   '#888888'),
            ('Section Count',     '4–8 typical',             'Not extracted',               'UNKNOWN',   '#888888'),
            ('Digital Signature', 'Signed by publisher',     'Not checked',                 'UNKNOWN',   '#888888'),
        ]

    fig, ax = plt.subplots(figsize=(6.8, max(1.5, len(rows) * 0.82 + 1.0)), facecolor='white')
    ax.set_facecolor('white'); ax.axis('off')
    ax.set_xlim(0, 10)
    ax.set_ylim(0, len(rows) * 0.82 + 1.2)

    headers = ['PE FIELD', 'EXPECTED (LEGITIMATE)', 'FOUND IN SAMPLE', 'VERDICT']

    col_x = [0.05, 2.1, 4.4, 7.2, 9.0]
    col_w = [2.0,  2.2, 2.7, 1.6, 0]

    # Header row
    hdr_y = len(rows) * 0.82 + 0.55
    for j, (hdr, x) in enumerate(zip(headers, col_x)):
        ax.add_patch(plt.Rectangle((x-0.05, hdr_y), col_w[j] if j<4 else 1.0, 0.65,
                                    facecolor='#333333', edgecolor='none'))
        ax.text(x + (col_w[j]/2 if j<4 else 0.5), hdr_y + 0.32, hdr, ha='center', va='center',
                fontsize=6.8, fontweight='bold', color='white', fontfamily='monospace')

    for i, (field, expected, found, verdict, vcol) in enumerate(rows):
        y = (len(rows) - i - 1) * 0.82 + 0.30
        bg = '#f8f8f8' if i % 2 == 0 else '#f0f0f0'
        ax.add_patch(plt.Rectangle((-0.05, y-0.28), 10.1, 0.72, facecolor=bg, edgecolor='none'))
        ax.text(col_x[0], y+0.08, field,    fontsize=7, color='#222222', fontfamily='monospace', fontweight='bold', va='center')
        ax.text(col_x[1], y+0.08, expected, fontsize=6.5, color='#555555', fontfamily='monospace', va='center')
        ax.text(col_x[2], y+0.08, found,    fontsize=6.5, color='#222222', fontfamily='monospace', va='center')
        # Verdict badge
        ax.add_patch(plt.Rectangle((col_x[3]-0.05, y-0.2), 1.6, 0.56,
                                    facecolor=vcol+'22', edgecolor=vcol, lw=0.8))
        ax.text(col_x[3]+0.75, y+0.08, verdict, ha='center', va='center',
                fontsize=6.5, fontweight='bold', color=vcol, fontfamily='monospace')

    fig.tight_layout(pad=0.3)
    return fig

# ── Confidence score breakdown ─────────────────────────────────────────────────
def make_confidence_breakdown(final_score=0, capa_caps=None, breakdown=None):
    # Build indicators dynamically from real compute_confidence_score() breakdown
    if breakdown:
        indicators = []
        for item in breakdown:
            earned = item.get('earned', 0)
            points = item.get('points', 1)
            ratio  = earned / points if points else 0
            if ratio >= 0.85:   col = '#cc0000'
            elif ratio >= 0.5:  col = '#cc6600'
            else:               col = '#888888'
            indicators.append((item.get('label','?'), earned, points, col, item.get('reason','')))
    else:
        indicators = [('No breakdown data', 0, 10, '#888888', 'breakdown not available')]
    total_score  = sum(s for _, s, _, _, _ in indicators)
    total_weight = sum(w for _, _, w, _, _ in indicators)

    fig, ax = plt.subplots(figsize=(6.8, 3.5), facecolor='white')
    ax.set_facecolor('white'); ax.axis('off')
    ax.set_xlim(0, 10); ax.set_ylim(0, len(indicators)+0.8)

    for i, (name, score, weight, col, note) in enumerate(reversed(indicators)):
        y = i * 0.9 + 0.2
        pct = score / weight if weight else 0
        bar_max = 3.5
        ax.add_patch(plt.Rectangle((3.5, y+0.1), bar_max, 0.55, facecolor='#eeeeee', edgecolor='none'))
        fill_w = bar_max * pct
        ax.add_patch(plt.Rectangle((3.5, y+0.1), fill_w, 0.55, facecolor=col, edgecolor='none', alpha=0.85))
        ax.text(3.42, y+0.38, name, ha='right', va='center',
                fontsize=7, color='#222222', fontfamily='monospace')
        ax.text(3.52 + bar_max, y+0.38, f'{score}/{weight}', ha='left', va='center',
                fontsize=7, color=col, fontfamily='monospace', fontweight='bold')
        # Note text: white if bar is long enough, dark otherwise
        note_x = 3.55 + min(fill_w * 0.5, bar_max * 0.5)
        note_color = 'white' if fill_w > 1.5 else '#777777'
        ax.text(3.55, y+0.38, note, ha='left', va='center',
                fontsize=5.8, color=note_color, fontfamily='monospace')

    ax.text(0.1, len(indicators)*0.9+0.35,
            f'TOTAL: {total_score}/{total_weight} = {final_score}/100' + ('  (CAPA partial due to packing)' if not capa_caps else ''),
            fontsize=8.5, fontweight='bold', color='#cc0000', fontfamily='monospace')

    fig.tight_layout(pad=0.3)
    return fig

# ── File timeline ──────────────────────────────────────────────────────────────
def make_file_timeline(compile_time='N/A', generated_at=''):
    fig, ax = plt.subplots(figsize=(6.8, 1.5), facecolor='white')
    ax.set_facecolor('white'); ax.axis('off')
    ax.set_xlim(0, 10); ax.set_ylim(0, 2.5)
    ax.plot([0.5, 9.5], [1.2, 1.2], color='#cccccc', lw=2, zorder=1)

    _ct = compile_time.split(' ')[0] if compile_time and compile_time != 'N/A' else '?'
    _gen = generated_at.split(' ')[0] if generated_at else '?'
    events = [
        (0.8,  _ct,   'Compile\nTimestamp',  '#cc0000', 'top'),
        (3.5,  _gen,  'Sample\nSubmitted',   '#333333', 'bottom'),
        (6.5,  _gen,  'ARIA\nAnalysis Run',  '#333333', 'top'),
        (9.2,  _gen,  'Report\nGenerated',   '#555555', 'bottom'),
    ]
    for x, date, label, col, side in events:
        ax.plot(x, 1.2, 'o', color=col, ms=9, zorder=3,
                markeredgecolor='white', markeredgewidth=1.5)
        y_text = 1.9 if side == 'top' else 0.5
        y_line_end = 1.55 if side == 'top' else 0.85
        ax.plot([x, x], [1.2, y_line_end], color='#cccccc', lw=1, zorder=2)
        ax.text(x, y_text, label, ha='center', va='center',
                fontsize=6.2, color=col, fontfamily='monospace',
                multialignment='center', fontweight='bold' if col=='#cc0000' else 'normal')
        ax.text(x, 1.2 + (0.25 if side=='top' else -0.25),
                date, ha='center', va='center',
                fontsize=5.8, color='#888888', fontfamily='monospace')

    fig.tight_layout(pad=0.2)
    return fig

# ══════════════════════════════════════════════════════════════════════════════
# Page background + header/footer canvas callback
# ══════════════════════════════════════════════════════════════════════════════
class ARIACanvas:
    def __init__(self, section=''):
        self.section = section

    def __call__(self, canv, doc):
        canv.saveState()
        # White background
        canv.setFillColor(colors.white)
        canv.rect(0, 0, W, H, fill=1, stroke=0)

        # Top red stripe
        canv.setFillColor(ACCENT_RED)
        canv.rect(0, H-2, W, 2, fill=1, stroke=0)

        # Header bar
        canv.setFillColor(colors.HexColor('#f1f1f1'))
        canv.rect(0, H-38, W, 36, fill=1, stroke=0)
        canv.setStrokeColor(colors.HexColor('#cccccc'))
        canv.setLineWidth(0.5)
        canv.line(0, H-38, W, H-38)

        # Header text
        canv.setFillColor(ACCENT_RED)
        canv.setFont('Courier-Bold', 9)
        canv.drawString(0.4*inch, H-22, 'ARIA')
        canv.setFillColor(colors.HexColor('#333333'))
        canv.setFont('Courier', 8)
        canv.drawString(0.75*inch, H-22, 'v1.0  |  MALWARE ANALYSIS REPORT')
        canv.setFillColor(colors.HexColor('#555555'))
        canv.setFont('Courier', 7.5)
        canv.drawRightString(W-0.4*inch, H-22, 'CLASSIFICATION: CONFIDENTIAL')

        # Footer
        canv.setFillColor(colors.HexColor('#f1f1f1'))
        canv.rect(0, 0, W, 28, fill=1, stroke=0)
        canv.setStrokeColor(colors.HexColor('#cccccc'))
        canv.setLineWidth(0.5)
        canv.line(0, 28, W, 28)

        canv.setFillColor(colors.HexColor('#555555'))
        canv.setFont('Courier', 7)
        canv.drawString(0.4*inch, 10, _cover_data.get('filename','N/A') + '  |  SHA256: ' + _cover_data.get('sha256','')[:16] + '...')
        canv.drawRightString(W-0.4*inch, 10, f'Page {doc.page}')

        canv.restoreState()

# Cover page callback
_cover_data = {}

def cover_callback(canv, doc):
    canv.saveState()
    # White background
    canv.setFillColor(colors.white)
    canv.rect(0,0,W,H,fill=1,stroke=0)

    # Top red stripe
    canv.setFillColor(ACCENT_RED)
    canv.rect(0, H-6, W, 6, fill=1, stroke=0)

    # Side accent bar
    canv.setFillColor(colors.HexColor('#f5f5f5'))
    canv.rect(0, 0, 0.18*inch, H, fill=1, stroke=0)
    canv.setFillColor(ACCENT_RED)
    canv.rect(0, 0, 0.05*inch, H, fill=1, stroke=0)

    # ARIA logo area
    canv.setFillColor(colors.HexColor('#f1f1f1'))
    canv.roundRect(0.5*inch, H-2.8*inch, W-1*inch, 1.8*inch, 8, fill=1, stroke=0)
    canv.setStrokeColor(colors.HexColor('#cccccc'))
    canv.setLineWidth(1)
    canv.roundRect(0.5*inch, H-2.8*inch, W-1*inch, 1.8*inch, 8, fill=0, stroke=1)

    # ARIA Title
    canv.setFillColor(ACCENT_RED)
    canv.setFont('Courier-Bold', 52)
    canv.drawCentredString(W/2, H-1.6*inch, 'ARIA')

    canv.setFillColor(colors.HexColor('#222222'))
    canv.setFont('Courier', 11)
    canv.drawCentredString(W/2, H-2.0*inch, 'Automated Reverse Engineering & Intelligence Agent')

    canv.setFillColor(colors.HexColor('#555555'))
    canv.setFont('Courier', 8.5)
    canv.drawCentredString(W/2, H-2.45*inch, 'MALWARE ANALYSIS REPORT  —  CONFIDENTIAL')

    # VERDICT badge
    canv.setFillColor(colors.HexColor('#fff0f0'))
    canv.roundRect(W/2-1.4*inch, H-4.3*inch, 2.8*inch, 1.1*inch, 6, fill=1, stroke=0)
    canv.setStrokeColor(ACCENT_RED)
    canv.setLineWidth(2)
    canv.roundRect(W/2-1.4*inch, H-4.3*inch, 2.8*inch, 1.1*inch, 6, fill=0, stroke=1)

    canv.setFillColor(colors.HexColor(_cover_data.get('verdict_color','#cc0000')))
    canv.setFont('Courier-Bold', 28)
    canv.drawCentredString(W/2, H-3.65*inch, _cover_data.get('verdict','MALICIOUS'))

    canv.setFillColor(colors.HexColor('#555555'))
    canv.setFont('Courier', 8)
    canv.drawCentredString(W/2, H-4.15*inch, 'ARIA PRIMARY VERDICT')

    # FAMILY badge — below verdict, no overlap
    family_y = H - 5.55*inch
    families = _cover_data.get('families', ['UNKNOWN'])
    family_str = '  /  '.join(families)
    label = 'SUSPECTED MALWARE FAMILIES' if len(families) > 1 else 'SUSPECTED MALWARE FAMILY'

    canv.setFillColor(colors.HexColor('#1a1a1a'))
    canv.roundRect(0.5*inch, family_y, W-1*inch, 0.82*inch, 6, fill=1, stroke=0)

    # Top label
    canv.setFillColor(colors.HexColor('#888888'))
    canv.setFont('Courier-Bold', 7)
    canv.drawString(0.75*inch, family_y + 0.60*inch, label)

    # Separator
    canv.setStrokeColor(colors.HexColor('#333333'))
    canv.setLineWidth(0.5)
    canv.line(0.75*inch, family_y + 0.54*inch, W-0.75*inch, family_y + 0.54*inch)

    # Family names — auto-size font to fit
    total_chars = len(family_str)
    if total_chars <= 20:   fam_font = 22
    elif total_chars <= 35: fam_font = 17
    elif total_chars <= 50: fam_font = 13
    else:                   fam_font = 10
    canv.setFillColor(colors.white)
    canv.setFont('Courier-Bold', fam_font)
    # Vertically center in lower half of box
    canv.drawString(0.75*inch, family_y + 0.16*inch, family_str)

    # Confidence badge
    canv.setFillColor(colors.HexColor('#cc0000'))
    canv.roundRect(W-2.3*inch, family_y + 0.14*inch, 1.65*inch, 0.34*inch, 4, fill=1, stroke=0)
    canv.setFillColor(colors.white)
    canv.setFont('Courier-Bold', 7.5)
    _clabel = 'HIGH' if _cover_data.get('score',0) >= 75 else 'MEDIUM' if _cover_data.get('score',0) >= 45 else 'LOW'
    canv.drawCentredString(W-1.475*inch, family_y + 0.26*inch, _clabel + ' CONFIDENCE')

    # File info box
    info_y = family_y - 1.2*inch
    canv.setFillColor(colors.HexColor('#f8f8f8'))
    canv.roundRect(0.5*inch, info_y, W-1*inch, 1.0*inch, 5, fill=1, stroke=0)
    canv.setStrokeColor(colors.HexColor('#cccccc'))
    canv.setLineWidth(0.5)
    canv.roundRect(0.5*inch, info_y, W-1*inch, 1.0*inch, 5, fill=0, stroke=1)

    fields = [
        ('FILE:',          _cover_data.get('filename','N/A')),
        ('SHA256:',        _cover_data.get('sha256','N/A')),
        ('GENERATED:',     _cover_data.get('generated_at','N/A')),
        ('THREAT LEVEL:',  'CRITICAL  |  Confidence: HIGH  |  Score: ' + str(_cover_data.get('score',0)) + '/100'),
    ]
    for i, (k, v) in enumerate(fields):
        y = info_y + 0.78*inch - i*0.185*inch
        canv.setFillColor(colors.HexColor('#cc0000'))
        canv.setFont('Courier-Bold', 7)
        canv.drawString(0.7*inch, y, k)
        canv.setFillColor(colors.HexColor('#222222'))
        canv.setFont('Courier', 7)
        canv.drawString(1.55*inch, y, v[:80])

    # TOC
    toc_y = info_y - 1.1*inch
    canv.setFillColor(colors.HexColor('#555555'))
    canv.setFont('Courier-Bold', 8)
    canv.drawString(0.5*inch, toc_y + 0.15*inch, 'TABLE OF CONTENTS')
    canv.setStrokeColor(colors.HexColor('#cccccc'))
    canv.setLineWidth(0.5)
    canv.line(0.5*inch, toc_y+0.05*inch, W-0.5*inch, toc_y+0.05*inch)

    toc_items = [
        ('1.', 'Executive Summary (Non-Technical)', '2'),
        ('2.', 'Full Technical Analysis', '3'),
        ('3.', 'MITRE ATT&CK Mapping', '6'),
        ('4.', 'Indicators of Compromise', '7'),
        ('5.', 'Raw Tool Evidence', '8'),
    ]
    for i,(num,title,pg) in enumerate(toc_items):
        y2 = toc_y - 0.22*inch - i*0.22*inch
        canv.setFillColor(ACCENT_RED)
        canv.setFont('Courier-Bold', 8)
        canv.drawString(0.5*inch, y2, num)
        canv.setFillColor(colors.HexColor('#222222'))
        canv.setFont('Courier', 8)
        canv.drawString(0.7*inch, y2, title)
        canv.setFillColor(colors.HexColor('#555555'))
        canv.drawRightString(W-0.5*inch, y2, pg)

    # Footer
    canv.setFillColor(colors.HexColor('#f1f1f1'))
    canv.rect(0,0,W,28,fill=1,stroke=0)
    canv.setStrokeColor(colors.HexColor('#cccccc'))
    canv.setLineWidth(0.5)
    canv.line(0,28,W,28)
    canv.setFillColor(colors.HexColor('#555555'))
    canv.setFont('Courier', 7)
    canv.drawCentredString(W/2, 10, 'ARIA v1.0  —  CONFIDENTIAL MALWARE ANALYSIS REPORT  —  Page 1')

    canv.restoreState()

# ══════════════════════════════════════════════════════════════════════════════
# Styled paragraph helpers
# ══════════════════════════════════════════════════════════════════════════════
def make_styles():
    s = {}
    base = dict(fontName='Courier', textColor=TEXT_LGREY, backColor=None,
                leading=14, spaceAfter=4)

    s['h1'] = ParagraphStyle('h1', fontName='Courier-Bold', fontSize=14,
                              textColor=ACCENT_RED, spaceAfter=6, spaceBefore=10,
                              leading=18)
    s['h2'] = ParagraphStyle('h2', fontName='Courier-Bold', fontSize=10,
                              textColor=ACCENT_CYAN, spaceAfter=4, spaceBefore=8,
                              leading=14)
    s['h3'] = ParagraphStyle('h3', fontName='Courier-Bold', fontSize=9,
                              textColor=TEXT_WHITE, spaceAfter=3, spaceBefore=6)
    s['body'] = ParagraphStyle('body', fontName='Courier', fontSize=8,
                                textColor=TEXT_LGREY, leading=13, spaceAfter=4)
    s['bullet'] = ParagraphStyle('bullet', fontName='Courier', fontSize=8,
                                  textColor=TEXT_LGREY, leading=13, spaceAfter=3,
                                  leftIndent=12, bulletIndent=0)
    s['label'] = ParagraphStyle('label', fontName='Courier-Bold', fontSize=7.5,
                                 textColor=ACCENT_CYAN)
    s['mono'] = ParagraphStyle('mono', fontName='Courier', fontSize=7,
                                textColor=TEXT_GREY, leading=10)
    s['center'] = ParagraphStyle('center', fontName='Courier-Bold', fontSize=9,
                                  textColor=TEXT_WHITE, alignment=TA_CENTER)
    s['warn'] = ParagraphStyle('warn', fontName='Courier-Bold', fontSize=8,
                                textColor=ACCENT_RED, leading=13)
    return s

# ── Horizontal rule ────────────────────────────────────────────────────────────
def hr():
    return HRFlowable(width='100%', thickness=0.5, color=BORDER_DIM,
                      spaceAfter=6, spaceBefore=4)

# ── Section header block ───────────────────────────────────────────────────────
def section_header(text, st):
    return [
        Spacer(1, 0.08*inch),
        Paragraph(f'▌ {text}', st['h1']),
        hr(),
    ]

# ── KPI card row ───────────────────────────────────────────────────────────────
def kpi_row(items):
    """items = [(label, value, color), ...]"""
    cells = []
    for label, val, col in items:
        cell_data = [[Paragraph(f'<font color="#{col[1:]}">{val}</font>',
                                ParagraphStyle('kv', fontName='Courier-Bold',
                                               fontSize=18, textColor=colors.HexColor(col),
                                               alignment=TA_CENTER))],
                     [Paragraph(label, ParagraphStyle('kl', fontName='Courier',
                                                       fontSize=7, textColor=TEXT_GREY,
                                                       alignment=TA_CENTER))]]
        cells.append(cell_data)

    # Build as single row table
    row_data = [[Table([[Paragraph(f'<font size="18"><b>{val}</b></font>',
                                   ParagraphStyle('v', fontName='Courier-Bold',
                                                   fontSize=16, textColor=colors.HexColor(col),
                                                   alignment=TA_CENTER)),
                          Paragraph(label, ParagraphStyle('l', fontName='Courier',
                                                           fontSize=7, textColor=TEXT_GREY,
                                                           alignment=TA_CENTER))
                          ]])
                 for label, val, col in items]]

    # Simpler approach: just make a flat table
    vals_row = [Paragraph(f'<b>{val}</b>',
                           ParagraphStyle('v', fontName='Courier-Bold', fontSize=18,
                                          textColor=colors.HexColor(col), alignment=TA_CENTER))
                for label, val, col in items]
    labs_row = [Paragraph(label,
                           ParagraphStyle('l', fontName='Courier', fontSize=7,
                                          textColor=TEXT_GREY, alignment=TA_CENTER))
                for label, val, col in items]

    t = Table([vals_row, labs_row],
              colWidths=[W/len(items) - 1*inch/len(items)] * len(items))
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), BG_CARD),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [BG_CARD, BG_CARD]),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_DIM),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_DIM),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    return t

# ══════════════════════════════════════════════════════════════════════════════
# BUILD REPORT
# ══════════════════════════════════════════════════════════════════════════════
def build_report(out_path,
    d_filename='sample.exe',
    d_md5='N/A',
    d_sha1='N/A',
    d_sha256='N/A',
    d_ssdeep='N/A',
    d_imphash='N/A',
    d_score=92,
    d_verdict='MALICIOUS',
    d_verdict_color='#cc0000',
    d_score_color='#cc0000',
    d_generated_at='2026-03-12 20:13:57 UTC',
    d_file_size='5.16 MB',
    d_file_type='PE32+ executable for MS Windows (GUI), x86-64',
    d_vt_str='0/0',
    d_vt_malicious=0,
    d_vt_suspicious=0,
    d_vt_total=0,
    d_compile_time='2026-02-13 17:58:07  ⚠ FORGED',
    d_architecture='x86-64 (PE32+)',
    d_sections=None,
    d_section_names=None,
    d_section_entropies=None,
    d_pe_imports=None,
    d_tls_cbs=None,
    d_overlay=None,
    d_rich_header=False,
    d_authenticode=False,
    d_gh_funcs=0, d_gh_named=0, d_gh_imports=0,
    d_gh_suspicious=None,
    d_yara_hits=None,
    d_capa_caps=None,
    d_suspicious_imports=None,
    d_families=None,
    d_threat_type=None,
    d_aria_text='',
    d_analyst_notes='',
    d_radar_caps=None,
    d_breakdown=None,
):
    doc = SimpleDocTemplate(
        out_path, pagesize=letter,
        leftMargin=0.5*inch, rightMargin=0.5*inch,
        topMargin=0.7*inch, bottomMargin=0.5*inch,
    )

    st = make_styles()
    story = []

    # ── Populate module-level cover data for callback ─────────────────────────
    global _cover_data
    _cover_data = {
        'filename': d_filename,
        'sha256': d_sha256,
        'generated_at': d_generated_at,
        'score': d_score,
        'verdict': d_verdict,
        'verdict_color': d_verdict_color,
        'families': d_families or ['UNKNOWN'],
    }

    # ── Resolve defaults ───────────────────────────────────────────────────────
    if d_sections is None:
        d_sections = []
    if d_section_names is None:
        d_section_names = ['.text','.rdata','.pdata','.xdata','.idata','.reloc','/19','/97','.rsrc','overlay']
    if d_section_entropies is None:
        d_section_entropies = [6.09, 5.84, 6.16, 4.99, 4.63, 5.42, 5.92, 5.91, 4.78, 3.03]
    if d_tls_cbs is None:
        d_tls_cbs = []
    if d_overlay is None:
        d_overlay = {'offset':'0x20c200','size':3262027,'entropy':3.03}
    if d_gh_suspicious is None:
        d_gh_suspicious = []
    if d_yara_hits is None:
        d_yara_hits = ['Big_Numbers3','Advapi_Hash_API','CRC32_table','BASE64_table']
    if d_capa_caps is None:
        d_capa_caps = []
    if d_suspicious_imports is None:
        d_suspicious_imports = []
    if d_families is None:
        d_families = ['UNKNOWN']
    if d_radar_caps is None:
        d_radar_caps = {}

    sha256_short = d_sha256[:16] + '...' if len(d_sha256) > 16 else d_sha256
    tls_count    = len(d_tls_cbs) if d_tls_cbs else 0
    overlay_size = d_overlay.get('size', 0) if isinstance(d_overlay, dict) else 0
    overlay_mb   = f'{overlay_size/1024/1024:.2f} MB' if overlay_size else 'N/A'
    overlay_offset = d_overlay.get('offset','N/A') if isinstance(d_overlay, dict) else 'N/A'
    overlay_entropy= d_overlay.get('entropy', 0) if isinstance(d_overlay, dict) else 0

    # ── Derive dynamic capability list for capability matrix chart ─────────────
    _status_colors = {'CONFIRMED': '#cc0000', 'LIKELY': '#555555', 'POSSIBLE': '#888888'}
    _caps_for_matrix = []
    _seen_cap_names = set()
    for _c, _v in sorted(d_radar_caps.items(), key=lambda x: -x[1]):
        if _v == 0: continue
        _s = 'CONFIRMED' if _v >= 7 else 'LIKELY' if _v >= 4 else 'POSSIBLE'
        _caps_for_matrix.append((_c, _s))
        _seen_cap_names.add(_c.lower())
    # Add from suspicious imports if not already covered
    _import_cap_map = {
        'GetAsyncKeyState': 'Keylogging', 'SetWindowsHookExA': 'Keylogging',
        'SetWindowsHookExW': 'Keylogging',
        'GetClipboardData': 'Clipboard Theft',
        'BitBlt': 'Screen Capture', 'CreateCompatibleBitmap': 'Screen Capture',
        'OpenProcess': 'Process Injection', 'CreateRemoteThread': 'Remote Injection',
        'WinHttpSendRequest': 'C2 Comms', 'WinHttpConnect': 'C2 Comms',
        'IsDebuggerPresent': 'Anti-Debug', 'GetTickCount': 'Sandbox Evasion',
        'RegSetValueExA': 'Registry Persistence', 'RegSetValueExW': 'Registry Persistence',
        'CryptEncrypt': 'Encryption', 'VirtualAllocEx': 'Memory Injection',
        'WriteProcessMemory': 'Process Memory Write',
    }
    for _dll, _fn, _sig in (d_suspicious_imports or []):
        _cap = _import_cap_map.get(_fn)
        if _cap and _cap.lower() not in _seen_cap_names:
            _caps_for_matrix.append((_cap, 'CONFIRMED'))
            _seen_cap_names.add(_cap.lower())
    if not _caps_for_matrix:
        _caps_for_matrix = [('No significant capabilities detected', 'UNKNOWN')]

    # ── Derive kill chain steps from detected capabilities ─────────────────────
    _fn_short = d_filename[:16] + '..' if len(d_filename) > 16 else d_filename
    _kc_steps = [('DELIVERY', _fn_short + '\nexecuted')]
    if tls_count:
        _kc_steps.append(('EXECUTION', f'TLS callbacks\nbefore main()'))
    elif overlay_size:
        _kc_steps.append(('EXECUTION', 'Overlay decrypt\nat runtime'))
    else:
        _kc_steps.append(('EXECUTION', 'Entry point\nexecution'))
    _has_persist = d_radar_caps.get('Persistence', 0) > 0
    _has_inject  = d_radar_caps.get('Injection', 0) > 0
    if _has_persist:
        _kc_steps.append(('PERSISTENCE', 'Registry/Task\npersistence'))
    if _has_inject:
        _kc_steps.append(('INJECTION', 'Process inject\ninto targets'))
    _coll_parts = []
    if d_radar_caps.get('Keylogging', 0) > 0: _coll_parts.append('Keylog')
    if d_radar_caps.get('Screenshot', 0) > 0: _coll_parts.append('Screen')
    if d_radar_caps.get('Exfil', 0) > 0 or d_radar_caps.get('C2 Comms', 0) > 0:
        _coll_str = '+'.join(_coll_parts) + '\ncapture' if _coll_parts else 'Data\ncollected'
        _kc_steps.append(('COLLECTION', _coll_str))
        _c2_str = 'Encrypted data\nto C2'
        _aria_low = d_aria_text.lower()
        if 'telegram' in _aria_low: _c2_str = 'Encrypted data\nvia Telegram'
        elif 'http' in _aria_low:   _c2_str = 'Encrypted data\nvia HTTP(S)'
        _kc_steps.append(('EXFILTRATION', _c2_str))
    elif _coll_parts:
        _kc_steps.append(('COLLECTION', '+'.join(_coll_parts) + '\ncapture'))

    # ── PAGE 2: ONE-PAGER C-SUITE SUMMARY ────────────────────────────────────
    # Cover page is drawn by cover_callback (onFirstPage) — one PageBreak pushes
    # story content to page 2. Do NOT add a second PageBreak or page 2 goes blank.
    story.append(PageBreak())
    story += section_header('EXECUTIVE ONE-PAGER  —  C-SUITE BRIEFING', st)
    story.append(Paragraph(
        'Print-ready single-page summary for executive distribution.',
        ParagraphStyle('sub', fontName='Courier', fontSize=7.5, textColor=TEXT_GREY)))
    story.append(Spacer(1, 6))

    # Top strip: verdict + score + file
    op_top = Table([[
        Paragraph(f'<b><font color="{d_verdict_color}">{d_verdict}</font></b>',
                  ParagraphStyle('opv', fontName='Courier-Bold', fontSize=14,
                                 textColor=colors.HexColor(d_verdict_color), alignment=TA_CENTER)),
        Paragraph(f'<b><font color="{d_score_color}">{d_score}</font><font color="#333333">/100</font></b>',
                  ParagraphStyle('ops', fontName='Courier-Bold', fontSize=18,
                                 textColor=colors.HexColor(d_score_color), alignment=TA_CENTER)),
        [Paragraph(f'<b>{d_filename}</b>',
                   ParagraphStyle('opf', fontName='Courier-Bold', fontSize=9,
                                  textColor=colors.HexColor('#222222'))),
         Paragraph(f'SHA256: {sha256_short}',
                   ParagraphStyle('oph', fontName='Courier', fontSize=7,
                                  textColor=TEXT_GREY)),
         Paragraph(f'Generated: {d_generated_at}',
                   ParagraphStyle('opd', fontName='Courier', fontSize=7,
                                  textColor=TEXT_GREY))],
    ]], colWidths=[1.5*inch, 1.5*inch, 4.2*inch])
    op_top.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1), colors.HexColor('#fff0f0')),
        ('BOX',(0,0),(-1,-1),1.5,ACCENT_RED),
        ('INNERGRID',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
        ('ALIGN',(0,0),(1,-1),'CENTER'),
        ('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8),
        ('LEFTPADDING',(0,0),(-1,-1),8),
    ]))
    story.append(op_top)
    story.append(Spacer(1,8))

    # Two columns: capabilities + actions
    cap_col = [
        Paragraph('TOP CAPABILITIES DETECTED', st['h3']),
        Spacer(1,4),
    ]
    # Derive from radar_caps (confirmed first, then likely) and suspicious imports
    _exec_order = ([c for c, s in _caps_for_matrix if s == 'CONFIRMED'] +
                   [c for c, s in _caps_for_matrix if s == 'LIKELY'] +
                   [c for c, s in _caps_for_matrix if s not in ('CONFIRMED', 'LIKELY')])
    _exec_order = list(dict.fromkeys(_exec_order))[:8]
    _status_lookup = dict(_caps_for_matrix)
    _cap_descs = {
        'Keylogging': 'Records every keystroke', 'C2 Comms': 'Communicates with attacker server',
        'Persistence': 'Survives reboots', 'Injection': 'Injects into other processes',
        'Evasion': 'Evades analysis tools', 'Encryption': 'Encrypts data',
        'Exfil': 'Exfiltrates stolen data', 'Recon': 'Reconnaissance capability',
        'Screenshot': 'Captures screen/camera', 'Ransomware': 'File encryption capability',
        'Clipboard Theft': 'Steals copied data', 'Anti-Debug': 'Evades debuggers',
        'Sandbox Evasion': 'Detects sandbox environments', 'Process Injection': 'Injects into processes',
        'Remote Injection': 'Remote code injection', 'Registry Persistence': 'Registry-based persistence',
        'Memory Injection': 'Injects into process memory', 'Screen Capture': 'Captures screenshots',
    }
    caps = [(c.upper(), _cap_descs.get(c, f'Detected ({_status_lookup.get(c,"?").lower()})'))
            for c in _exec_order]
    if not caps:
        caps = [('NO CAPABILITIES DETECTED', 'Sample appears benign or unpacked')]
    for cap, desc in caps:
        cap_col.append(Paragraph(
            f'<font color="#cc0000">■</font>  <b>{cap}</b> — {desc}',
            ParagraphStyle('opc', fontName='Courier', fontSize=7.5,
                           textColor=colors.HexColor('#222222'), leading=13)))

    act_col = [
        Paragraph('IMMEDIATE ACTIONS', st['h3']),
        Spacer(1,4),
    ]
    acts = [
        ('1', 'ISOLATE infected systems now'),
        ('2', 'BLOCK identified C2 domains at firewall'),
        ('3', 'RESET all exposed passwords'),
        ('4', 'NOTIFY insurer + legal counsel'),
        ('5', 'SCAN org for file hash IOCs'),
    ]
    for num, act in acts:
        act_col.append(Paragraph(
            f'<font color="#cc0000"><b>{num}.</b></font>  {act}',
            ParagraphStyle('opa', fontName='Courier', fontSize=7.5,
                           textColor=colors.HexColor('#222222'), leading=14)))

    act_col += [
        Spacer(1,8),
        Paragraph('THREAT LEVEL', st['h3']),
        Spacer(1,4),
        fig_to_rl(make_gauge(d_score), 2.8, 1.6),
    ]

    op_cols = Table([[cap_col, act_col]], colWidths=[3.5*inch, 3.7*inch])
    op_cols.setStyle(TableStyle([
        ('VALIGN',(0,0),(-1,-1),'TOP'),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('BACKGROUND',(0,0),(-1,-1),BG_CARD),
        ('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8),
        ('LEFTPADDING',(0,0),(-1,-1),8),('RIGHTPADDING',(0,0),(-1,-1),8),
    ]))
    story.append(op_cols)
    story.append(Spacer(1,8))

    # Business impact cost estimate
    story.append(Paragraph('ESTIMATED BUSINESS IMPACT', st['h2']))
    _is_ransomware = 'RANSOMWARE' in (d_families or [])
    cost_data = [
        ['IMPACT CATEGORY',          'LOW ESTIMATE',  'HIGH ESTIMATE', 'BASIS'],
        ['Incident Response',        '$50,000',       '$250,000',      'IR firm engagement, forensics'],
    ]
    if _is_ransomware:
        cost_data.append(['Ransomware Recovery', '$100,000', '$500,000', 'System restore, downtime costs'])
    else:
        cost_data.append(['Data Breach / Exfil Response', '$50,000', '$300,000', 'Credential reset, data containment'])
    cost_data += [
        ['Data Breach Notification', '$25,000',       '$150,000',      'Legal, notification, credit monitoring'],
        ['Regulatory Fines (GDPR)',  '$50,000',       '$20,000,000',   '2–4% annual turnover exposure'],
        ['Reputational / Customer',  '$75,000',       '$1,000,000+',   'Customer churn, PR, trust loss'],
        ['TOTAL EXPOSURE',           '$300,000',      '$21,900,000+',  'Assumes full compromise scenario'],
    ]
    cost_rows = []
    for i, row in enumerate(cost_data):
        if i == 0:
            cost_rows.append([Paragraph(f'<b>{c}</b>', st['label']) for c in row])
        else:
            is_total = i == len(cost_data)-1
            cost_rows.append([
                Paragraph(f'<b>{row[0]}</b>' if is_total else row[0],
                          ParagraphStyle('cf', fontName='Courier-Bold' if is_total else 'Courier',
                                         fontSize=7.5, textColor=ACCENT_RED if is_total else TEXT_LGREY)),
                Paragraph(row[1], ParagraphStyle('cl', fontName='Courier-Bold' if is_total else 'Courier',
                                                  fontSize=7.5, textColor=colors.HexColor('#555555'))),
                Paragraph(f'<b>{row[2]}</b>' if is_total else row[2],
                          ParagraphStyle('ch', fontName='Courier-Bold' if is_total else 'Courier',
                                         fontSize=7.5, textColor=ACCENT_RED if is_total else TEXT_LGREY)),
                Paragraph(row[3], st['mono']),
            ])
    cost_table = Table(cost_rows, colWidths=[2.1*inch, 1.0*inch, 1.15*inch, 2.95*inch])
    cost_ts = [
        ('BACKGROUND',(0,0),(-1,0),BG_MID),
        ('ROWBACKGROUNDS',(0,1),(-1,-2),[BG_CARD, ROW_ALT]),
        ('BACKGROUND',(0,-1),(-1,-1),colors.HexColor('#fff0f0')),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.3,BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('LEFTPADDING',(0,0),(-1,-1),6),('VALIGN',(0,0),(-1,-1),'TOP'),
    ]
    cost_table.setStyle(TableStyle(cost_ts))
    story.append(cost_table)

    # ── PAGE 3: EXECUTIVE SUMMARY ─────────────────────────────────────────────
    story.append(PageBreak())
    story += section_header('SECTION 1 — EXECUTIVE SUMMARY', st)

    story.append(Paragraph(
        'FOR: Senior Leadership &amp; Non-Technical Stakeholders', st['h2']))
    story.append(Spacer(1, 4))

    # KPI bar
    kpi = kpi_row([
        ('THREAT SCORE',  f'{d_score}/100', d_score_color),
        ('VT DETECTIONS', d_vt_str, '#555555'),
        ('CAPABILITIES',  str(len(d_suspicious_imports))+'+', d_score_color),
        ('ARIA VERDICT',  d_verdict, d_verdict_color),
    ])
    story.append(kpi)
    story.append(Spacer(1, 10))

    # Gauge + donut side by side
    gauge_img   = fig_to_rl(make_gauge(d_score), 3.6, 2.0)
    donut_img   = fig_to_rl(make_detection_donut(d_vt_malicious, d_vt_suspicious, d_vt_total), 2.0, 2.0)
    conf_img    = fig_to_rl(make_confidence_bar(d_score), 3.8, 0.5)

    gauge_table = Table([[gauge_img, donut_img]],
                        colWidths=[3.8*inch, 2.5*inch])
    gauge_table.setStyle(TableStyle([
        ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
        ('ALIGN',(0,0),(-1,-1),'CENTER'),
        ('BACKGROUND',(0,0),(-1,-1), BG_CARD),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),8),
        ('BOTTOMPADDING',(0,0),(-1,-1),8),
    ]))
    story.append(gauge_table)
    story.append(Spacer(1,6))
    story.append(conf_img)
    story.append(Spacer(1,10))

    # Plain-english summary box — derived from actual analysis data
    _families_str = '/'.join(d_families) if d_families != ['UNKNOWN'] else 'UNKNOWN'
    _vt_note = (f'with {d_vt_malicious} of {d_vt_total} antivirus engines detecting it'
                if d_vt_malicious > 0 else
                'despite potentially low antivirus detection rate')
    _cap_count_confirmed = len([c for c, s in _caps_for_matrix if s == 'CONFIRMED'])
    _cap_count_total     = len([c for c, s in _caps_for_matrix if s in ('CONFIRMED','LIKELY','POSSIBLE')])
    summary_text = [
        Paragraph('<b>WHAT IS THIS FILE?</b>', st['h3']),
        Paragraph(
            f'A <b>{_families_str}</b> identified as {d_verdict.lower()} by ARIA static analysis, '
            f'{_vt_note}. Static analysis identified {_cap_count_confirmed} confirmed and '
            f'{_cap_count_total - _cap_count_confirmed} probable/possible malicious capabilities '
            f'through PE analysis, YARA, Ghidra, and CAPA examination.',
            st['body']),
        Spacer(1,6),
        Paragraph('<b>WHAT CAN IT DO TO YOUR ORGANIZATION?</b>', st['h3']),
    ]
    # Build bullets from confirmed/likely capabilities
    _cap_bullets = {
        'keylogging': ('⌨', 'Record every keystroke — captures passwords, credentials, messages'),
        'clipboard theft': ('📋', 'Steal clipboard content — banking codes, OTPs, copied passwords'),
        'screen capture': ('📷', 'Capture screenshots and potentially webcam images'),
        'screenshot': ('📷', 'Capture screenshots and potentially webcam images'),
        'ransomware': ('💾', 'Encrypt files and demand ransom payment'),
        'encryption': ('🔒', 'Encrypt data for exfiltration or C2 communications'),
        'persistence': ('🔗', 'Survive reboots — reinstalls itself automatically'),
        'registry persistence': ('🔗', 'Survive reboots via registry or scheduled tasks'),
        'process injection': ('💉', 'Inject into other running programs to hide activity'),
        'remote injection': ('💉', 'Inject malicious code into legitimate processes'),
        'c2 comms': ('📡', 'Silently communicate with attacker-controlled servers'),
        'exfil': ('📤', 'Upload stolen data to external servers'),
        'anti-debug': ('🛡', 'Evade antivirus and analysis tools'),
        'sandbox evasion': ('🛡', 'Detect and evade sandbox analysis environments'),
        'memory injection': ('💉', 'Inject code into process memory'),
        'process memory write': ('💉', 'Write malicious code into other processes'),
    }
    _shown_bullets = []
    for _cn, _cs in _caps_for_matrix:
        _key = _cn.lower()
        if _key in _cap_bullets and _cap_bullets[_key] not in _shown_bullets:
            _shown_bullets.append(_cap_bullets[_key])
    # Fallback if no matches
    if not _shown_bullets:
        _shown_bullets = [('⚠', f'Capability detected: {c}') for c, _ in _caps_for_matrix[:5]]
    bullets_exec = _shown_bullets[:8]
    for icon, txt in bullets_exec:
        summary_text.append(Paragraph(f'<b>{icon}</b>  {txt}', st['bullet']))

    summary_text += [
        Spacer(1,6),
        Paragraph('<b>HOW DANGEROUS IS IT?  (1–5 scale)</b>', st['h3']),
    ]
    # ── Capability flags — used by both danger rows and risk matrix ───────────
    _confirmed_caps  = {c.lower() for c, s in _caps_for_matrix if s == 'CONFIRMED'}
    _has_persistence = any(k in _confirmed_caps for k in ('persistence','registry persistence'))
    _has_c2          = any(k in _confirmed_caps for k in ('c2 comms','c2'))
    _has_exfil       = any(k in _confirmed_caps for k in ('exfil','exfiltration'))
    _has_injection   = any(k in _confirmed_caps for k in ('injection','process injection','remote injection'))
    _has_ransomware  = 'RANSOMWARE' in (d_families or [])

    def _danger_score(raw):
        """Convert 0–10 capability score to 1–5 display score."""
        s = max(1, min(5, round(raw / 2))) if raw > 0 else 0
        dots = '●' * s + '○' * (5 - s)
        col  = ('#ef4444' if s >= 5 else '#f97316' if s >= 4 else
                '#eab308' if s >= 3 else '#3b82f6' if s >= 2 else '#22c55e')
        return dots, f'{s}/5', col

    # Data Theft Risk — driven by keylogging/clipboard/exfil capabilities
    _dt_score = max(
        d_radar_caps.get('Keylogging', 0), d_radar_caps.get('Exfil', 0),
        d_radar_caps.get('Screenshot', 0), d_radar_caps.get('C2 Comms', 0))
    if any(f in (d_families or []) for f in ['INFOSTEALER','KEYLOGGER','BANKER']): _dt_score = max(_dt_score, 9)
    _dt_dots, _dt_str, _dt_col = _danger_score(_dt_score)

    # Business Disruption — ransomware, injection, persistence
    _bd_score = max(
        d_radar_caps.get('Ransomware', 0), d_radar_caps.get('Injection', 0),
        d_radar_caps.get('Persistence', 0))
    if 'RANSOMWARE' in (d_families or []): _bd_score = max(_bd_score, 10)
    _bd_dots, _bd_str, _bd_col = _danger_score(_bd_score)

    # AV Evasion: how well the sample evades AV — computed from VT detection rate
    _av_evasion_raw   = 1.0 - (d_vt_malicious / d_vt_total) if d_vt_total > 0 else 0.5
    _av_evasion_score = round(_av_evasion_raw * 5)
    _av_evasion_dots  = '●' * _av_evasion_score + '○' * (5 - _av_evasion_score)
    _av_evasion_str   = f'{_av_evasion_score}/5'
    _av_evasion_color = ('#ef4444' if _av_evasion_score >= 4 else
                         '#f97316' if _av_evasion_score >= 3 else
                         '#eab308' if _av_evasion_score >= 2 else
                         '#22c55e')

    # Spread Potential — injection + persistence = can replicate/spread
    _sp_score = max(d_radar_caps.get('Injection', 0), d_radar_caps.get('Persistence', 0))
    if _has_injection and _has_persistence: _sp_score = max(_sp_score, 8)
    _sp_dots, _sp_str, _sp_col = _danger_score(_sp_score)

    # Recovery Difficulty — ransomware/encryption hard to recover; stealer = credential reset needed
    _rd_score = max(d_radar_caps.get('Ransomware', 0), d_radar_caps.get('Encryption', 0),
                    d_radar_caps.get('Persistence', 0))
    if 'RANSOMWARE' in (d_families or []): _rd_score = 10
    elif _has_exfil and _has_persistence: _rd_score = max(_rd_score, 7)
    _rd_dots, _rd_str, _rd_col = _danger_score(_rd_score)

    danger_rows = [
        ('Data Theft Risk',       _dt_dots,         _dt_str,         _dt_col),
        ('Business Disruption',   _bd_dots,         _bd_str,         _bd_col),
        ('AV Evasion',            _av_evasion_dots, _av_evasion_str, _av_evasion_color),
        ('Spread Potential',      _sp_dots,         _sp_str,         _sp_col),
        ('Recovery Difficulty',   _rd_dots,         _rd_str,         _rd_col),
    ]
    d_data = [[
        Paragraph(r, ParagraphStyle('dr', fontName='Courier', fontSize=8, textColor=TEXT_LGREY)),
        Paragraph(f'<font color="{c}">{dots}</font>',
                  ParagraphStyle('dd', fontName='Courier', fontSize=10, textColor=colors.HexColor(c))),
        Paragraph(f'<b><font color="{c}">{score}</font></b>',
                  ParagraphStyle('ds', fontName='Courier-Bold', fontSize=9,
                                 textColor=colors.HexColor(c), alignment=TA_RIGHT)),
    ] for r, dots, score, c in danger_rows]

    d_table = Table(d_data, colWidths=[3.2*inch, 2.0*inch, 1.0*inch])
    d_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), BG_CARD),
        ('ROWBACKGROUNDS', (0,0), (-1,0), [BG_CARD]),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [ROW_ALT, BG_CARD]),
        ('BOX', (0,0), (-1,-1), 0.5, BORDER_DIM),
        ('INNERGRID', (0,0), (-1,-1), 0.3, BORDER_DIM),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
    ]))
    summary_text.append(d_table)

    exec_table = Table([[summary_text]], colWidths=[W - 1.1*inch])
    exec_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), BG_MID),
        ('BOX', (0,0), (-1,-1), 1, ACCENT_RED),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(exec_table)
    story.append(Spacer(1, 8))

    # Immediate actions
    story.append(Paragraph('<b>IMMEDIATE ACTIONS REQUIRED</b>', st['warn']))
    actions = [
        '1.  ISOLATE any system that may have run this file — disconnect from network immediately',
        '2.  RESET all passwords on potentially exposed accounts',
        '3.  NOTIFY cyber insurance carrier and legal counsel',
        '4.  SCAN all systems organization-wide for this file hash',
        '5.  DO NOT re-connect infected systems until forensically cleared',
    ]
    for a in actions:
        story.append(Paragraph(a, st['bullet']))
    story.append(Spacer(1, 10))

    # Kill Chain
    story.append(Paragraph('ATTACK KILL CHAIN', st['h2']))
    story.append(fig_to_rl(make_kill_chain(_kc_steps), 7.0, 2.4))
    story.append(Spacer(1, 10))

    # ── Dynamic risk rating — derived entirely from evidence ──────────────────
    _vt_rate = (d_vt_malicious / d_vt_total) if d_vt_total > 0 else 0.0

    if _vt_rate >= 0.5 and (_has_persistence or _has_c2 or len(_confirmed_caps) >= 3):
        _likelihood_label = 'VERY HIGH'
    elif _vt_rate >= 0.2 or len(_confirmed_caps) >= 3:
        _likelihood_label = 'HIGH'
    elif _vt_rate > 0 or len(_confirmed_caps) >= 1:
        _likelihood_label = 'MEDIUM'
    else:
        _likelihood_label = 'LOW'

    if _has_ransomware and 'encryption' in _confirmed_caps:
        _impact_label = 'CATASTROPHIC'
    elif len(_confirmed_caps) >= 4 or (_has_exfil and _has_persistence):
        _impact_label = 'CRITICAL'
    elif len(_confirmed_caps) >= 2 or _has_exfil or _has_persistence:
        _impact_label = 'HIGH'
    elif len(_confirmed_caps) >= 1:
        _impact_label = 'MEDIUM'
    else:
        _impact_label = 'LOW'

    _risk_matrix_map = {
        ('VERY HIGH','CATASTROPHIC'): 'CRITICAL', ('VERY HIGH','CRITICAL'): 'CRITICAL',
        ('VERY HIGH','HIGH'):         'CRITICAL', ('VERY HIGH','MEDIUM'):   'HIGH',
        ('VERY HIGH','LOW'):          'HIGH',     ('HIGH','CATASTROPHIC'):  'CRITICAL',
        ('HIGH','CRITICAL'):          'CRITICAL', ('HIGH','HIGH'):          'CRITICAL',
        ('HIGH','MEDIUM'):            'HIGH',     ('HIGH','LOW'):           'MEDIUM',
        ('MEDIUM','CATASTROPHIC'):    'HIGH',     ('MEDIUM','CRITICAL'):    'HIGH',
        ('MEDIUM','HIGH'):            'MEDIUM',   ('MEDIUM','MEDIUM'):      'MEDIUM',
        ('MEDIUM','LOW'):             'LOW',      ('LOW','CATASTROPHIC'):   'MEDIUM',
        ('LOW','CRITICAL'):           'MEDIUM',   ('LOW','HIGH'):           'LOW',
        ('LOW','MEDIUM'):             'LOW',      ('LOW','LOW'):            'LOW',
    }
    _overall_risk       = _risk_matrix_map.get((_likelihood_label, _impact_label), 'HIGH')
    _risk_color         = ('#cc0000' if _overall_risk in ('CRITICAL','CATASTROPHIC')
                           else '#f97316' if _overall_risk == 'HIGH'
                           else '#eab308' if _overall_risk == 'MEDIUM' else '#22c55e')
    _likelihood_color   = ('#cc0000' if _likelihood_label in ('VERY HIGH','HIGH')
                           else '#f97316' if _likelihood_label == 'MEDIUM' else '#22c55e')
    _impact_color_hex   = ('#cc0000' if _impact_label in ('CATASTROPHIC','CRITICAL')
                           else '#f97316' if _impact_label == 'HIGH'
                           else '#eab308' if _impact_label == 'MEDIUM' else '#22c55e')

    _confirmed_cap_list = ', '.join(c for c, s in _caps_for_matrix if s == 'CONFIRMED') or 'None confirmed'
    _impact_cascade     = ('One infection can cascade across the entire organization.'
                           if _overall_risk == 'CRITICAL'
                           else 'Significant organizational impact if not contained promptly.'
                           if _overall_risk == 'HIGH'
                           else 'Contained impact — limit lateral movement to reduce exposure.')

    # Risk Matrix — keep title + content together
    rm_img = fig_to_rl(make_risk_matrix(_likelihood_label, _impact_label), 2.8, 2.4)
    rm_tbl = Table([[rm_img,
                     [Paragraph(f'<b>LIKELIHOOD: {_likelihood_label}</b>',
                                ParagraphStyle('rl', fontName='Courier-Bold', fontSize=8,
                                               textColor=colors.HexColor(_likelihood_color))),
                      Paragraph(
                          f'This {"/".join(d_families)} was detected by {d_vt_str} VT engines at submission time. '
                          + ('Signature-based defenses provide strong coverage for this sample.'
                             if d_vt_total > 0 and _vt_rate >= 0.5
                             else 'Signature-based defenses may offer limited protection for this sample.'),
                          st['body']),
                      Spacer(1, 6),
                      Paragraph(f'<b>IMPACT: {_impact_label}</b>',
                                ParagraphStyle('ri', fontName='Courier-Bold', fontSize=8,
                                               textColor=colors.HexColor(_impact_color_hex))),
                      Paragraph(
                          f'Confirmed capabilities include: {_confirmed_cap_list}. {_impact_cascade}',
                          st['body']),
                      Spacer(1, 6),
                      Paragraph(f'<b>OVERALL RISK: {_overall_risk}</b>',
                                ParagraphStyle('ro', fontName='Courier-Bold', fontSize=10,
                                               textColor=colors.HexColor(_risk_color))),
                      ]
                     ]],
                  colWidths=[3.0*inch, 4.2*inch])
    rm_tbl.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),
                                 ('LEFTPADDING',(1,0),(1,0),12),
                                 ('TOPPADDING',(0,0),(-1,-1),4)]))
    story.append(KeepTogether([
        Paragraph('RISK MATRIX POSITION', st['h2']),
        Spacer(1, 4),
        rm_tbl,
    ]))

    # ── PAGE 3: TECHNICAL ANALYSIS ────────────────────────────────────────────
    story.append(PageBreak())
    story += section_header('SECTION 2 — FULL TECHNICAL ANALYSIS', st)

    # Verdict block
    v_data = [[
        Paragraph('<b>VERDICT</b>', st['label']),
        Paragraph(f'<b><font color="{d_verdict_color}">{d_verdict}</font></b>',
                  ParagraphStyle('vv', fontName='Courier-Bold', fontSize=11,
                                 textColor=colors.HexColor(d_verdict_color))),
        Paragraph('<b>CONFIDENCE</b>', st['label']),
        Paragraph(f'<b><font color="{d_score_color}">{"HIGH" if d_score >= 75 else "MEDIUM" if d_score >= 45 else "LOW"} ({d_score}/100)</font></b>',
                  ParagraphStyle('vc', fontName='Courier-Bold', fontSize=10,
                                 textColor=colors.HexColor(d_score_color))),
    ],[
        Paragraph('<b>THREAT TYPE</b>', st['label']),
        Paragraph(d_threat_type or '/'.join(d_families) or 'UNKNOWN', st['body']),
        Paragraph('<b>FAMILY</b>', st['label']),
        Paragraph('/'.join(d_families), st['body']),
    ],[
        Paragraph('<b>PACKER</b>', st['label']),
        Paragraph(
            (f'Encrypted overlay — {overlay_entropy:.2f} entropy' if overlay_size and overlay_entropy >= 7.0
             else f'Packed/compressed overlay — {overlay_entropy:.2f} entropy' if overlay_size and overlay_entropy >= 5.0
             else 'Overlay present — low entropy (possible data)' if overlay_size
             else 'No packer detected — standard PE layout'),
            st['body']),
        Paragraph('<b>MOTIVATION</b>', st['label']),
        Paragraph(
            ('Financial — credential theft / data exfiltration'
             if any(f in (d_families or []) for f in ['INFOSTEALER','KEYLOGGER','BANKER'])
             else 'Operational disruption / extortion'
             if 'RANSOMWARE' in (d_families or [])
             else 'Remote access / persistent backdoor'
             if 'RAT' in (d_families or []) or 'BACKDOOR' in (d_families or [])
             else 'Unknown — inferred from ' + '/'.join(d_families or ['UNKNOWN'])),
            st['body']),
    ]]
    v_table = Table(v_data, colWidths=[1.3*inch, 2.5*inch, 1.3*inch, 2.1*inch])
    v_table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1), BG_CARD),
        ('BOX',(0,0),(-1,-1),0.5, BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.3, BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),5),
        ('BOTTOMPADDING',(0,0),(-1,-1),5),
        ('LEFTPADDING',(0,0),(-1,-1),7),
        ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
    ]))
    story.append(v_table)
    story.append(Spacer(1,8))

    # 2a. PE Header
    story.append(Paragraph('[1] PE HEADER ANALYSIS', st['h2']))
    _sec_count = len(d_section_names) if d_section_names else 0
    _nonstandard = [n for n in d_section_names if n and not n.startswith('.')] if d_section_names else []
    _sections_str = f'{_sec_count} sections'
    if _nonstandard:
        _ns_preview = ' '.join(_nonstandard[:6]) + ('...' if len(_nonstandard) > 6 else '')
        _sections_str += f'  ({len(_nonstandard)} non-standard: {_ns_preview})'
    pe_facts = [
        ('Architecture',    d_architecture),
        ('Compile Time',    d_compile_time),
        ('Sections',        _sections_str if _sec_count else 'Not extracted'),
        ('Rich Header',     ('PRESENT' if d_rich_header else 'NOT PRESENT — header stripped or hand-crafted')),
        ('Authenticode',    'SIGNED' if d_authenticode else 'NOT SIGNED — unsigned binary'),
        ('TLS Callbacks',   f'{tls_count} callbacks — early execution before main()' if tls_count else 'NONE DETECTED'),
        ('Overlay',         f'{overlay_mb} at {overlay_offset} — encrypted payload (entropy {overlay_entropy:.4f})' if overlay_size else 'NOT PRESENT'),
    ]
    pe_data = [[Paragraph(k, st['label']), Paragraph(v, st['body'])] for k,v in pe_facts]
    pe_table = Table(pe_data, colWidths=[1.4*inch, 5.8*inch])
    pe_table.setStyle(TableStyle([
        ('ROWBACKGROUNDS',(0,0),(-1,-1),[BG_CARD, ROW_ALT]),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.3,BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),4),
        ('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('LEFTPADDING',(0,0),(-1,-1),6),
        ('VALIGN',(0,0),(-1,-1),'TOP'),
    ]))
    story.append(pe_table)
    story.append(Spacer(1,8))

    # Entropy chart
    story.append(Paragraph('[2] SECTION ENTROPY ANALYSIS', st['h2']))
    story.append(Paragraph(
        'Entropy measures randomness — values above 6.0 indicate compression or encryption. '
        'Red dashed line = suspicion threshold.',
        st['body']))
    story.append(fig_to_rl(make_entropy_chart(d_section_names, d_section_entropies), 6.8, 2.8))
    story.append(Spacer(1,8))

    # Capability matrix
    _cap_fig, _cap_h = make_capability_matrix(_caps_for_matrix)
    story.append(KeepTogether([
        Paragraph('[3] CAPABILITY ASSESSMENT', st['h2']),
        Spacer(1, 4),
        fig_to_rl(_cap_fig, 6.8, _cap_h),
    ]))
    story.append(Spacer(1,8))

    # Radar chart + imports side by side
    story.append(Paragraph('[4] THREAT RADAR  &amp;  SUSPICIOUS IMPORTS', st['h2']))

    # ── Dynamic radar: capabilities derived from analysis ──────────────────────
    radar_fig, radar_size = make_radar(
        caps=list(d_radar_caps.keys()),
        vals=list(d_radar_caps.values())
    )
    radar_img = fig_to_rl(radar_fig, radar_size, radar_size)

    # ── Dynamic imports table: all suspicious imports from this sample ─────────
    suspicious_imports = d_suspicious_imports or []

    imp_table_data = [[Paragraph(f'<b>{c}</b>', st['label'])
                       for c in ['DLL', 'IMPORT', 'SIGNIFICANCE']]]
    for dll, imp, sig in suspicious_imports:
        imp_table_data.append([
            Paragraph(dll, ParagraphStyle('id', fontName='Courier-Bold', fontSize=6.5,
                                           textColor=colors.HexColor('#555555'))),
            Paragraph(imp, ParagraphStyle('im', fontName='Courier-Bold', fontSize=6.5,
                                           textColor=colors.HexColor('#222222'))),
            Paragraph(sig, ParagraphStyle('is', fontName='Courier', fontSize=6.2,
                                           textColor=TEXT_GREY, leading=9)),
        ])

    imp_table = Table(imp_table_data, colWidths=[0.72*inch, 1.5*inch, 1.95*inch])
    imp_table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0), BG_MID),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[BG_CARD, ROW_ALT]),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.3,BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),2),
        ('BOTTOMPADDING',(0,0),(-1,-1),2),
        ('LEFTPADDING',(0,0),(-1,-1),4),
    ]))

    combined = Table([[radar_img, imp_table]],
                     colWidths=[radar_size*inch + 0.1*inch,
                                W - radar_size*inch - 1.2*inch])
    combined.setStyle(TableStyle([
        ('VALIGN',(0,0),(-1,-1),'TOP'),
        ('LEFTPADDING',(0,0),(-1,-1),2),
        ('RIGHTPADDING',(0,0),(-1,-1),2),
    ]))
    story.append(combined)

    # ── PAGE: MITRE ATT&CK ────────────────────────────────────────────────────
    story.append(PageBreak())
    story += section_header('SECTION 3 — MITRE ATT&CK MAPPING', st)

    # Build MITRE ATT&CK table from suspicious imports + radar caps + CAPA
    _mitre_base = {
        'GetAsyncKeyState':         ['T1056','Input Capture','T1056.001 Keylogging','HIGH'],
        'SetWindowsHookExA':        ['T1056','Input Capture','T1056.001 Keylogging','HIGH'],
        'SetWindowsHookExW':        ['T1056','Input Capture','T1056.001 Keylogging','HIGH'],
        'GetClipboardData':         ['T1115','Clipboard Data','—','HIGH'],
        'BitBlt':                   ['T1113','Screen Capture','—','HIGH'],
        'CreateCompatibleBitmap':   ['T1113','Screen Capture','—','HIGH'],
        'OpenProcess':              ['T1055','Process Injection','—','HIGH'],
        'VirtualAllocEx':           ['T1055','Process Injection','T1055.001 DLL Injection','HIGH'],
        'WriteProcessMemory':       ['T1055','Process Injection','T1055.012 Hollowing','HIGH'],
        'CreateRemoteThread':       ['T1055','Process Injection','T1055.003 Thread','HIGH'],
        'IsDebuggerPresent':        ['T1497','Virtualization/Sandbox Evasion','T1497.001 System Checks','HIGH'],
        'GetTickCount':             ['T1497','Virtualization/Sandbox Evasion','T1497.003 Time-Based Evasion','HIGH'],
        'Sleep':                    ['T1497','Virtualization/Sandbox Evasion','T1497.003 Time','MED'],
        'WinHttpConnect':           ['T1071','Application Layer Protocol','T1071.001 Web','HIGH'],
        'WinHttpSendRequest':       ['T1071','Application Layer Protocol','T1071.001 Web','HIGH'],
        'RegSetValueExA':           ['T1547','Boot/Logon Autostart','T1547.001 Registry Run','HIGH'],
        'RegSetValueExW':           ['T1547','Boot/Logon Autostart','T1547.001 Registry Run','HIGH'],
        'CryptEncrypt':             ['T1027','Obfuscated Files','T1027 Encrypted/Encoded','HIGH'],
        'CryptGenRandom':           ['T1573','Encrypted Channel','T1573.001 Symmetric Cryptography','MED'],
        'CreateToolhelp32Snapshot': ['T1057','Process Discovery','—','HIGH'],
    }
    _mitre_seen_tids = set()
    _mitre_rows_dyn = []
    for _dll, _fn, _sig in (d_suspicious_imports or []):
        if _fn in _mitre_base and _mitre_base[_fn][0] not in _mitre_seen_tids:
            _mr = _mitre_base[_fn]
            _mitre_rows_dyn.append([_mr[0], _mr[1], _mr[2], f'{_fn} import detected', _mr[3]])
            _mitre_seen_tids.add(_mr[0])
    # Add from radar_caps if not already covered
    _cap_mitre = {
        'Evasion': ['T1562','Impair Defenses','T1562.001 Disable or Modify Tools','Anti-analysis behaviors detected','MED'],
        'Exfil':   ['T1041','Exfiltration Over C2 Channel','—','C2 comms + data theft detected','MED'],
        'Ransomware': ['T1486','Data Encrypted for Impact','—','File encryption capability','MED'],
    }
    for _cn, _cs in _caps_for_matrix:
        if _cn in _cap_mitre and _cap_mitre[_cn][0] not in _mitre_seen_tids:
            _mr2 = _cap_mitre[_cn]
            _mitre_rows_dyn.append(_mr2)
            _mitre_seen_tids.add(_mr2[0])
    # Also add packing/overlay if detected
    if overlay_size and 'T1027' not in _mitre_seen_tids:
        _mitre_rows_dyn.append(['T1027','Obfuscated Files/Info','T1027.002 Software Packing','Encrypted overlay detected','HIGH'])
        _mitre_seen_tids.add('T1027')
    if tls_count and 'T1055' not in _mitre_seen_tids:
        _mitre_rows_dyn.append(['T1055','Process Injection','—','TLS pre-execution callbacks','MED'])
    # Add CAPA-derived techniques if available
    for _cap_item in (d_capa_caps or [])[:5]:
        _ct = str(_cap_item).strip()
        _mitre_rows_dyn.append(['CAPA', _ct[:40], '—', 'CAPA detection', 'MED'])
    if not _mitre_rows_dyn:
        _mitre_rows_dyn.append(['N/A','No MITRE techniques mapped','—','Insufficient static data','LOW'])
    mitre_data = [['TID', 'TECHNIQUE', 'SUB-TECHNIQUE', 'EVIDENCE', 'CONF']] + _mitre_rows_dyn

    conf_colors = {'HIGH': '#ef4444', 'MED': '#f97316', 'LOW': '#eab308'}

    m_rows = []
    for i, row in enumerate(mitre_data):
        if i == 0:
            m_rows.append([Paragraph(f'<b>{c}</b>', st['label']) for c in row])
        else:
            conf = row[4]
            col = conf_colors.get(conf, '#94a3b8')
            m_rows.append([
                Paragraph(row[0], ParagraphStyle('tid', fontName='Courier-Bold', fontSize=7.5,
                                                  textColor=ACCENT_CYAN)),
                Paragraph(row[1], ParagraphStyle('tt', fontName='Courier', fontSize=7.5,
                                                  textColor=TEXT_LGREY)),
                Paragraph(row[2], ParagraphStyle('ts', fontName='Courier', fontSize=7,
                                                  textColor=TEXT_GREY)),
                Paragraph(row[3], ParagraphStyle('te', fontName='Courier', fontSize=7,
                                                  textColor=TEXT_GREY)),
                Paragraph(f'<b><font color="{col}">{conf}</font></b>',
                          ParagraphStyle('tc', fontName='Courier-Bold', fontSize=7.5,
                                         textColor=colors.HexColor(col),
                                         alignment=TA_CENTER)),
            ])

    m_table = Table(m_rows, colWidths=[0.7*inch, 1.6*inch, 1.5*inch, 2.3*inch, 0.6*inch])
    m_style = [
        ('BACKGROUND',(0,0),(-1,0), BG_MID),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[BG_CARD, ROW_ALT]),
        ('BOX',(0,0),(-1,-1),0.5, BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.3, BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),4),
        ('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('LEFTPADDING',(0,0),(-1,-1),5),
        ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
    ]
    # Color HIGH rows background subtly
    for i, row in enumerate(mitre_data[1:], 1):
        if row[4] == 'HIGH':
            m_style.append(('BACKGROUND',(0,i),(-1,i), colors.HexColor('#fff0f0')))
    m_table.setStyle(TableStyle(m_style))
    story.append(m_table)

    # Legend
    story.append(Spacer(1,8))
    legend_data = [[
        Paragraph('<font color="#ef4444">■</font> HIGH — Confirmed evidence', st['mono']),
        Paragraph('<font color="#f97316">■</font> MED — Probable based on artifacts', st['mono']),
        Paragraph('<font color="#eab308">■</font> LOW — Circumstantial indication', st['mono']),
    ]]
    leg_t = Table(legend_data, colWidths=[2.4*inch]*3)
    leg_t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),BG_MID),
                                ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
                                ('TOPPADDING',(0,0),(-1,-1),5),
                                ('BOTTOMPADDING',(0,0),(-1,-1),5)]))
    story.append(leg_t)

    # ── IOC TABLE ──────────────────────────────────────────────────────────────
    story.append(PageBreak())
    story += section_header('SECTION 4 — INDICATORS OF COMPROMISE', st)

    ioc_data = [['TYPE', 'VALUE', 'CONTEXT']]
    if d_md5  != 'N/A': ioc_data.append(['MD5',     d_md5,  'Primary file hash'])
    if d_sha1 != 'N/A': ioc_data.append(['SHA1',    d_sha1, 'Primary file hash'])
    if d_sha256!='N/A': ioc_data.append(['SHA256',  d_sha256,'Primary file hash'])
    if d_imphash!='N/A':ioc_data.append(['IMPHASH', d_imphash,'Import hash — family clustering'])
    if d_ssdeep!='N/A': ioc_data.append(['SSDEEP',  d_ssdeep,'Fuzzy hash — variant detection'])
    ioc_data.append(['FILENAME', d_filename, 'Submitted filename'])
    # Extract domains/IPs from ARIA text
    import re as _re
    _seen_ioc = set()
    for dom in _re.findall(r'api\.[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}|\b(?:\d{1,3}\.){3}\d{1,3}\b', d_aria_text)[:20]:
        dom = _re.sub(r'[^a-zA-Z0-9./_-]', '', dom)
        if dom and dom not in _seen_ioc:
            _seen_ioc.add(dom)
            ioc_data.append(['DOMAIN/IP', dom, 'Extracted from ARIA analysis'])

    type_colors = {
        'MD5':'#333333','SHA1':'#333333','SHA256':'#333333','IMPHASH':'#333333',
        'SSDEEP':'#555555','FILENAME':'#cc0000','DOMAIN':'#cc0000','REGISTRY':'#555555',
        'PATH':'#444444','STRING':'#333333',
    }

    ioc_rows = []
    for i, row in enumerate(ioc_data):
        if i == 0:
            ioc_rows.append([Paragraph(f'<b>{c}</b>', st['label']) for c in row])
        else:
            tc = type_colors.get(row[0], '#333333')
            ioc_rows.append([
                Paragraph(f'<b><font color="{tc}">{row[0]}</font></b>',
                          ParagraphStyle('it', fontName='Courier-Bold', fontSize=7.5,
                                         textColor=colors.HexColor(tc))),
                Paragraph(row[1], ParagraphStyle('iv', fontName='Courier', fontSize=6.8,
                                                  textColor=TEXT_LGREY)),
                Paragraph(row[2], st['mono']),
            ])

    ioc_table = Table(ioc_rows, colWidths=[0.75*inch, 3.5*inch, 2.95*inch])
    ioc_table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),BG_MID),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[BG_CARD, ROW_ALT]),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.3,BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),4),
        ('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('LEFTPADDING',(0,0),(-1,-1),6),
        ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
    ]))
    story.append(ioc_table)
    story.append(Spacer(1, 6))

    # ssdeep explanation
    ssdeep_box = Table([[
        [Paragraph('<b>SSDEEP FUZZY HASH — VARIANT DETECTION</b>', st['h3']),
         Paragraph(
             'ssdeep is a fuzzy (context-triggered piecewise) hash. Unlike MD5/SHA256 which change '
             'completely with any byte modification, ssdeep scores similarity between files. '
             'A score of 70+ indicates the same malware family. Use this hash to cluster variants '
             'and detect repackaged copies of this sample.',
             st['body']),
         Spacer(1,4),
         Paragraph(
             d_ssdeep if d_ssdeep and d_ssdeep != 'N/A' else '(ssdeep not available — tool not installed or binary too small)',
             ParagraphStyle('ss', fontName='Courier', fontSize=6.5, textColor=TEXT_GREY)),
        ]
    ]], colWidths=[W-1.1*inch])
    ssdeep_box.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1),BG_CARD),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('LEFTPADDING',(0,0),(-1,-1),10),('RIGHTPADDING',(0,0),(-1,-1),10),
        ('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8),
    ]))
    story.append(ssdeep_box)

    # ── ANOMALY TABLE ──────────────────────────────────────────────────────────
    story.append(PageBreak())
    story += section_header('SECTION 5 — DEEP TECHNICAL ANALYSIS', st)

    story.append(Paragraph('PE ANOMALY ANALYSIS — EXPECTED VS FOUND', st['h2']))
    story.append(Paragraph(
        'Side-by-side comparison of what legitimate software looks like versus what was found in this sample.',
        st['body']))
    story.append(Spacer(1,4))
    # Build anomaly rows from actual PE data
    _anomaly_rows = []
    if d_compile_time and d_compile_time != 'N/A':
        _ct_verdict = ('FORGED', '#cc0000') if 'FORG' in d_compile_time.upper() else ('CHECK', '#888888')
        _anomaly_rows.append(('Compile Timestamp', 'Past date, realistic', d_compile_time[:35], _ct_verdict[0], _ct_verdict[1]))
    _anomaly_rows.append(('Rich Header', 'Present (MSVC builds)', 'PRESENT' if d_rich_header else 'ABSENT',
                           'OK' if d_rich_header else 'STRIPPED', '#222222' if d_rich_header else '#cc0000'))
    if _sec_count:
        _sec_out_of_range = _sec_count < 4 or _sec_count > 8
        if _sec_out_of_range:
            _sec_verdict, _sec_col = 'SUSPICIOUS', '#cc0000'
            _sec_found = f'{_sec_count} sections (out of range)'
        elif _nonstandard:
            _sec_verdict, _sec_col = 'NON-STANDARD', '#f97316'
            _sec_found = f'{_sec_count} sections ({len(_nonstandard)} non-standard: {" ".join(_nonstandard[:3])})'
        else:
            _sec_verdict, _sec_col = 'NORMAL', '#222222'
            _sec_found = f'{_sec_count} sections'
        _anomaly_rows.append(('Section Count', '4–8 typical', _sec_found, _sec_verdict, _sec_col))
    _anomaly_rows.append(('Digital Signature', 'Signed by publisher', 'SIGNED' if d_authenticode else 'UNSIGNED',
                           'OK' if d_authenticode else 'UNSIGNED', '#222222' if d_authenticode else '#555555'))
    if overlay_size:
        _anomaly_rows.append(('Overlay', 'None or small', f'{overlay_mb} payload', 'PACKED', '#cc0000'))
    if tls_count:
        _anomaly_rows.append(('TLS Callbacks', 'Rare in legitimate sw', f'{tls_count} callback{"s" if tls_count!=1 else ""}', 'SUSPICIOUS', '#cc0000'))
    if not _anomaly_rows:
        _anomaly_rows = [('PE Structure', 'Normal expected', 'Not fully analyzed', 'UNKNOWN', '#888888')]
    _anomaly_h = max(2.0, len(_anomaly_rows) * 0.82 + 1.2)
    story.append(fig_to_rl(make_anomaly_visual(_anomaly_rows), 7.0, _anomaly_h))
    story.append(Spacer(1,10))

    # String categories
    story.append(Paragraph('STRING CATEGORY BREAKDOWN', st['h2']))
    story.append(Paragraph(
        'FLOSS string extraction complete. '
        'Breakdown by functional category (based on suspicious string patterns identified):',
        st['body']))
    story.append(Spacer(1,4))
    story.append(fig_to_rl(make_string_categories(), 6.8, 2.6))
    story.append(Spacer(1,10))

    # File timeline
    story.append(Paragraph('FILE TIMELINE', st['h2']))
    story.append(fig_to_rl(make_file_timeline(d_compile_time, d_generated_at), 7.0, 1.5))
    story.append(Spacer(1,6))
    _ct_warning = ''
    if d_compile_time and d_compile_time != 'N/A' and 'FORG' in d_compile_time.upper():
        _ct_warning = f'⚠  Compile timestamp appears FORGED ({d_compile_time.split()[0]}). Malware authors routinely forge timestamps to bypass time-based detection rules.'
    elif d_compile_time and d_compile_time != 'N/A':
        _ct_warning = f'Compile timestamp: {d_compile_time}. Verify this is plausible for the suspected malware campaign timeline.'
    if _ct_warning:
        story.append(Paragraph(_ct_warning,
            ParagraphStyle('tl', fontName='Courier', fontSize=7.5, textColor=ACCENT_RED, leading=12)))
    story.append(Spacer(1,10))

    # Overlay deep dive — only show real data, never fabricate content
    story.append(Paragraph('OVERLAY DEEP DIVE', st['h2']))
    if overlay_size and overlay_size > 0:
        _unpack_method = (f'{tls_count} TLS callback{"s" if tls_count!=1 else ""} fire before entry point'
                          if tls_count else 'Mechanism TBD — requires dynamic analysis')
        _entropy_note = ('High entropy — strongly suggests packed/encrypted payload' if overlay_entropy >= 7.0
                         else 'Moderate entropy — compressed or structured data'  if overlay_entropy >= 5.0
                         else 'Low entropy — structured data or plaintext config')
        _interp = ('Encrypted/packed payload — high confidence' if overlay_entropy >= 6.5
                   else 'Likely appended data or secondary stage' if overlay_entropy >= 4.0
                   else 'Structured appended data — config or resources')
        overlay_data = [
            ['FIELD',            'VALUE',                              'SIGNIFICANCE'],
            ['Offset',           f'{overlay_offset}',                 'Start of overlay in file'],
            ['Size',             f'{overlay_size:,} bytes ({overlay_mb})', 'Size of appended data'],
            ['Entropy',          f'{overlay_entropy:.4f}',            _entropy_note],
            ['Interpretation',   _interp,                             'Based on entropy and position'],
            ['Unpacking method', _unpack_method,                      'Execution mechanism before entry point'],
        ]
    else:
        overlay_data = [
            ['FIELD',   'VALUE',       'SIGNIFICANCE'],
            ['Status',  'NOT PRESENT', 'No data appended after the last PE section'],
            ['Impact',  'N/A',         'Payload is embedded within PE sections or memory-only'],
        ]
    ov_rows = []
    for i, row in enumerate(overlay_data):
        if i == 0:
            ov_rows.append([Paragraph(f'<b>{c}</b>', st['label']) for c in row])
        else:
            ov_rows.append([Paragraph(row[j], st['body'] if j>0 else st['label']) for j in range(3)])
    ov_table = Table(ov_rows, colWidths=[1.6*inch, 2.4*inch, 3.2*inch])
    ov_table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),BG_MID),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[BG_CARD,ROW_ALT]),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.3,BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('LEFTPADDING',(0,0),(-1,-1),6),('VALIGN',(0,0),(-1,-1),'TOP'),
    ]))
    story.append(ov_table)
    story.append(Spacer(1,10))

    # TLS Callback explanation — conditional on whether sample actually has TLS callbacks
    story.append(Paragraph('TLS CALLBACKS — WHY THEY ARE DANGEROUS', st['h2']))
    if tls_count > 0:
        _tls_content = [
            Paragraph('<b>WHAT ARE TLS CALLBACKS?</b>', st['h3']),
            Paragraph(
                'Thread Local Storage (TLS) callbacks are functions registered in the PE TLS directory '
                'that execute <b>before the program entry point</b>. Most debuggers attach at the entry point — '
                'meaning TLS callback code runs before any analyst tooling is active.',
                st['body']),
            Spacer(1,6),
            Paragraph(f'<b>THIS SAMPLE HAS {tls_count} TLS CALLBACK{"S" if tls_count != 1 else ""}:</b>', st['h3']),
            Paragraph(', '.join(str(cb) for cb in (d_tls_cbs or [])[:6]), st['mono']),
            Spacer(1,4),
            Paragraph('• <b>Anti-debug checks</b> may run before main() — IsDebuggerPresent can fire in TLS', st['bullet']),
            Paragraph('• <b>Payload decryption</b> — encrypted sections may be decrypted during TLS phase', st['bullet']),
            Paragraph('• <b>Environment fingerprinting</b> — sandbox detection before main code executes', st['bullet']),
            Spacer(1,6),
            Paragraph(
                '⚠  Dynamic analysis must use a debugger that supports TLS callback breakpoints '
                '(x64dbg with TLS plugin, WinDbg with sxe ld). Standard entry-point debugging will miss this code.',
                ParagraphStyle('tlsw', fontName='Courier', fontSize=7.5, textColor=ACCENT_RED, leading=12)),
        ]
    else:
        _tls_content = [
            Paragraph('<b>WHAT ARE TLS CALLBACKS?</b>', st['h3']),
            Paragraph(
                'Thread Local Storage (TLS) callbacks are functions registered in the PE TLS directory '
                'that execute <b>before the program entry point</b>. Most debuggers attach at the entry point — '
                'meaning TLS callback code runs before any analyst tooling is active.',
                st['body']),
            Spacer(1,6),
            Paragraph('<b>TLS CALLBACKS IN THIS SAMPLE: NONE DETECTED</b>', st['h3']),
            Paragraph(
                'No TLS callbacks are present. Execution begins at the standard PE entry point. '
                'Standard entry-point debugging applies — no special TLS breakpoints required.',
                st['body']),
            Spacer(1,4),
            Paragraph(
                'Note: Absence of TLS callbacks is the norm for most binaries and does not reduce '
                'the malicious assessment — it simply means pre-entry execution is not used.',
                ParagraphStyle('tlsn', fontName='Courier', fontSize=7.5, textColor=colors.HexColor('#555555'), leading=12)),
        ]
    tls_box = Table([[_tls_content]], colWidths=[W-1.1*inch])
    tls_box.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#fff8f8')),
        ('BOX',(0,0),(-1,-1),0.8,BORDER_DIM),
        ('LEFTPADDING',(0,0),(-1,-1),10),('RIGHTPADDING',(0,0),(-1,-1),10),
        ('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8),
    ]))
    story.append(tls_box)

    # ── THREAT ACTOR PROFILING ─────────────────────────────────────────────────
    story.append(PageBreak())
    story += section_header('SECTION 6 — THREAT ACTOR PROFILING', st)

    story.append(Paragraph(
        'Attribution derived entirely from static artifacts — no dynamic analysis performed. '
        'Confidence: MEDIUM.',
        st['body']))
    story.append(Spacer(1,8))

    # Build actor profiling from actual analysis data
    _actor_rows_data = [
        ('Architecture',        d_architecture,                         'Target platform and compiler toolchain indicator'),
        ('Compile Timestamp',   d_compile_time,                         'Forged timestamps indicate operational awareness' if d_compile_time and d_compile_time != 'N/A' else 'Standard compile time'),
        ('Rich Header',         'PRESENT' if d_rich_header else 'ABSENT',
         'PRESENT — standard compiler artifact; no evasion indicator' if d_rich_header
         else 'ABSENT in large binary — likely stripped for evasion or hand-crafted' if d_file_size and 'MB' in str(d_file_size) and float(str(d_file_size).split()[0]) > 1.0
         else 'ABSENT — less significant in small binary'),
        ('Authenticode',        'SIGNED' if d_authenticode else 'UNSIGNED', 'Unsigned binaries bypass certificate pinning but reduce credibility'),
        ('Packer',              'Custom packer detected' if overlay_size else 'No packer detected',
         'Custom packers suggest skilled developer avoiding common signatures' if overlay_size
         else 'No packing detected — payload embedded in standard PE sections'),
        ('TLS Callbacks',       f'{tls_count} callbacks' if tls_count else 'None detected',
         'TLS callbacks present — may execute anti-debug and decryption before main()' if tls_count
         else 'No TLS callbacks — standard entry point execution, no pre-main code'),
        ('Families detected',   '/'.join(d_families),                  'Multi-capability malware indicates resource-rich threat actor'),
        ('Motivation',          'Financial — credential theft / data exfiltration' if any(f in d_families for f in ['INFOSTEALER','KEYLOGGER','BANKER']) else '/'.join(d_families) + ' operations', 'Inferred from detected capabilities'),
    ]
    # Add paths/strings extracted from ARIA text if available
    import re as _re_actor
    _paths_raw = _re_actor.findall(r'[CD]:\\[^\s\'"<>]{4,60}', d_aria_text)
    _paths_seen = set()
    _paths_deduped = []
    for _p in _paths_raw:
        _p_clean = _p.rstrip('`,. ')
        if _p_clean not in _paths_seen:
            _paths_seen.add(_p_clean)
            _paths_deduped.append(_p_clean)
    for _p in _paths_deduped[:3]:
        _actor_rows_data.append(('Path artifact', _p[:60], 'Build/test path leak — possible OPSEC failure'))
    actor_data = [['ARTIFACT', 'VALUE', 'INFERENCE']] + [list(r) for r in _actor_rows_data]
    actor_rows = []
    for i, row in enumerate(actor_data):
        if i == 0:
            actor_rows.append([Paragraph(f'<b>{c}</b>', st['label']) for c in row])
        else:
            actor_rows.append([
                Paragraph(row[0], st['label']),
                Paragraph(row[1], ParagraphStyle('av', fontName='Courier', fontSize=7,
                                                   textColor=colors.HexColor('#222222'))),
                Paragraph(row[2], st['mono']),
            ])
    actor_table = Table(actor_rows, colWidths=[1.7*inch, 2.0*inch, 3.5*inch])
    actor_table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),BG_MID),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[BG_CARD,ROW_ALT]),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.3,BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('LEFTPADDING',(0,0),(-1,-1),6),('VALIGN',(0,0),(-1,-1),'TOP'),
    ]))
    story.append(actor_table)
    story.append(Spacer(1,10))

    # Detection gap analysis — built dynamically from actual sample data only
    story.append(Paragraph('DETECTION GAP ANALYSIS — WHY AV MISSED THIS', st['h2']))
    _gap_rows_raw = []
    # Overlay/packer: only if present
    if overlay_size and overlay_size > 0:
        _gap_rows_raw.append(['Custom packer/crypter', 'Encrypted overlay payload appended to PE', 'Defeats signature-based scanning — HIGH'])
    # Rich Header stripped: only if actually absent
    if not d_rich_header:
        _gap_rows_raw.append(['Rich Header stripped', 'Compiler fingerprint removed from PE header', 'Defeats compiler-based clustering — MED'])
    # TLS: only if actually present
    if tls_count > 0:
        _gap_rows_raw.append(['TLS pre-execution code', f'{tls_count} callback(s) run before AV hooks attach', 'Defeats dynamic sandbox analysis — HIGH'])
    # Unsigned: only if unsigned
    if not d_authenticode:
        _gap_rows_raw.append(['Unsigned binary', 'No Authenticode signature — no publisher verification', 'Bypasses certificate-based trust checks — MED'])
    # High VT but still partial miss: if some engines missed it
    _vt_missed = d_vt_total - d_vt_malicious if d_vt_total > 0 else 0
    if d_vt_total > 0 and _vt_missed > 0:
        _gap_rows_raw.append([f'{_vt_missed}/{d_vt_total} engines missed it',
                               'Heuristic evasion, polymorphic strings, or engine-specific blind spots',
                               f'Partial signature coverage — {_vt_missed} engines bypassed — MED'])
    elif d_vt_total == 0 or d_vt_malicious == 0:
        _gap_rows_raw.append(['Zero VT history', 'New/unreported sample at submission', 'No community signatures yet — CRITICAL'])
    # String obfuscation: always applies if we have obfuscated or encrypted strings
    _has_obfusc = any('obfusc' in d_aria_text.lower() for _ in [1]) or any('encrypt' in d_aria_text.lower() for _ in [1])
    if _has_obfusc or overlay_size:
        _gap_rows_raw.append(['String obfuscation', 'Runtime decryption hides IOCs from static scanners', 'Defeats static string scanning — HIGH'])
    # High suspicious import count evasion
    if d_suspicious_imports and len(d_suspicious_imports) >= 5:
        _gap_rows_raw.append(['Direct API import obfuscation', f'{len(d_suspicious_imports)} suspicious APIs called directly', 'Signature-based import analysis may miss runtime-resolved APIs — MED'])
    # If nothing fired (very clean evasion profile), note that
    if not _gap_rows_raw:
        _gap_rows_raw.append(['No specific evasion techniques identified', 'Sample does not exhibit common evasion patterns', 'Standard detection methods should apply — LOW'])
    gap_data = [['EVASION TECHNIQUE', 'MECHANISM', 'AV BYPASS EFFECTIVENESS']] + _gap_rows_raw
    gap_rows = []
    for i, row in enumerate(gap_data):
        if i == 0:
            gap_rows.append([Paragraph(f'<b>{c}</b>', st['label']) for c in row])
        else:
            eff_col = '#cc0000' if 'HIGH' in row[2] or 'CRITICAL' in row[2] else '#555555'
            gap_rows.append([
                Paragraph(row[0], st['label']),
                Paragraph(row[1], st['body']),
                Paragraph(f'<font color="{eff_col}">{row[2]}</font>',
                          ParagraphStyle('ge', fontName='Courier', fontSize=7,
                                         textColor=colors.HexColor(eff_col))),
            ])
    gap_table = Table(gap_rows, colWidths=[1.7*inch, 2.6*inch, 2.9*inch])
    gap_table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),BG_MID),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[BG_CARD,ROW_ALT]),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.3,BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('LEFTPADDING',(0,0),(-1,-1),6),('VALIGN',(0,0),(-1,-1),'TOP'),
    ]))
    story.append(gap_table)
    story.append(Spacer(1,10))

    # Confidence score breakdown
    story.append(KeepTogether([
        Paragraph(f'CONFIDENCE SCORE BREAKDOWN — {d_score}/100', st['h2']),
        Paragraph(
            'Each of the 10 indicators below fed into the deterministic confidence score. '
            'Score is computed regardless of VT result — ARIA overrides clean VT with static evidence.',
            st['body']),
        Spacer(1,4),
        fig_to_rl(make_confidence_breakdown(d_score, d_capa_caps, d_breakdown or []), 7.0, 3.5),
    ]))
    story.append(Spacer(1, 8))

    # Why not 100 / why 100 explanation
    score = d_score
    if score == 100:
        score_title = f'WHY THIS SAMPLE SCORES {d_score}/100'
        score_color = '#cc0000'
        score_body = (
            'A score of 100/100 is assigned only when every indicator reaches its maximum weight '
            'with no partial credits or mitigating factors. This sample received full marks on all '
            '10 indicators — confirmed capabilities, packed payload, forged metadata, unsigned binary, '
            'dense malicious imports, overlay, TLS callbacks, YARA matches, and dynamic C2 infrastructure. '
            'No indicator returned a neutral or benign signal. This represents the highest possible '
            'confidence that this file is malicious with no ambiguity.'
        )
        score_items = []
    elif score >= 80:
        score_title = f'WHY THIS SAMPLE SCORES {d_score}/100 AND NOT HIGHER'
        score_color = '#cc0000'
        score_body = (
            f'The score of {d_score}/100 reflects overwhelmingly malicious indicators. '
            f'Points not earned reflect absence of optional evasion features '
            f'(overlay, TLS callbacks, Rich Header stripping) — their absence is normal and does not '
            f'reduce the malicious assessment. These indicators add to the score when present; '
            f'they are not penalties when absent.'
        )
        score_items = []
    else:
        score_title = f'WHY THIS SAMPLE SCORES {score}/100'
        score_color = '#555555'
        score_body = f'Score of {score}/100 indicates moderate confidence. See indicator breakdown above.'
        score_items = []

    why_content = [
        Paragraph(score_title,
                  ParagraphStyle('wt', fontName='Courier-Bold', fontSize=9,
                                 textColor=colors.HexColor(score_color))),
        Spacer(1, 4),
        Paragraph(score_body, st['body']),
    ]
    for item in score_items:
        why_content.append(Spacer(1, 4))
        why_content.append(Paragraph(f'• {item}', st['bullet']))

    _why_combined = Paragraph(f"<b>{score_title}</b><br/><br/>{score_body}", ParagraphStyle('wb2', fontName='Courier', fontSize=8, leading=12, textColor=colors.HexColor('#222222'), wordWrap='CJK'))
    why_box = Table([[_why_combined]], colWidths=[W - 1.1*inch])
    why_box.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1), colors.HexColor('#fff8f8') if score >= 80 else BG_CARD),
        ('BOX',(0,0),(-1,-1), 0.8, colors.HexColor(score_color)),
        ('LEFTPADDING',(0,0),(-1,-1),10),('RIGHTPADDING',(0,0),(-1,-1),10),
        ('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8),
    ]))
    story.append(why_box)

    # ── DETECTION SIGNATURES ───────────────────────────────────────────────────
    story.append(PageBreak())
    story += section_header('SECTION 7 — DETECTION SIGNATURES', st)

    # YARA rule
    story.append(Paragraph('AUTO-GENERATED YARA RULE', st['h2']))
    story.append(Paragraph(
        'Generated from unique static indicators. Deploy to YARA-compatible scanners, EDR, or SIEM.',
        st['body']))
    story.append(Spacer(1,4))

    _yara_name = "_".join(d_families[:2]) + "_" + d_filename.replace(".","_").replace(" ","_")
    _yara_date = d_generated_at.split(' ')[0] if d_generated_at else '2026-01-01'
    _yara_strings = ""
    _yara_seen = set()
    _yara_idx = 1
    for fn in (d_gh_suspicious or []):
        if fn in _yara_seen:
            continue
        _yara_seen.add(fn)
        _yara_strings += f'        $func{_yara_idx} = "{fn}" ascii\n'
        _yara_idx += 1
        if _yara_idx > 8:
            break
    if not _yara_strings:
        # Fall back to hash-based condition only — no fabricated string indicators
        _yara_strings = f'        // No unique string indicators extracted from Ghidra analysis\n'
    _families_str = "/".join(d_families)
    yara_rule = (
        f"rule {_yara_name} {{\n"
        f"    meta:\n"
        f"        description = \"Detects {_families_str} - {d_filename}\"\n"
        f"        author      = \"ARIA v1.0 - OpenClaw\"\n"
        f"        date        = \"{_yara_date}\"\n"
        f"        severity    = \"{_overall_risk}\"\n"
        f"        hash_md5    = \"{d_md5}\"\n"
        f"        hash_sha256 = \"{d_sha256[:32]}...\"\n"
        f"    strings:\n"
        f"{_yara_strings}"
        f"    condition:\n"
        + (f"        uint16(0) == 0x5A4D and (1 of ($func*))\n"
           if _yara_idx > 1
           else f"        uint16(0) == 0x5A4D  // hash-match only — no extracted strings\n")
        + f"}}\n"
    )

    yara_tbl = Table([[Paragraph(yara_rule,
                                  ParagraphStyle('yr', fontName='Courier', fontSize=6.5,
                                                  textColor=colors.HexColor('#222222'),
                                                  leading=10, backColor=colors.HexColor('#f8f8f8')))
                        ]], colWidths=[W-1.1*inch])
    yara_tbl.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#f8f8f8')),
        ('BOX',(0,0),(-1,-1),0.8,BORDER_DIM),
        ('LEFTPADDING',(0,0),(-1,-1),10),('RIGHTPADDING',(0,0),(-1,-1),10),
        ('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8),
    ]))
    story.append(yara_tbl)
    story.append(Spacer(1,10))

    # Sigma rule
    story.append(Paragraph('SIGMA RULE — SIEM DETECTION STUB', st['h2']))
    story.append(Paragraph(
        'Deploy to Splunk, Elastic, or any Sigma-compatible SIEM. '
        'Alerts on registry persistence and hidden scheduled task creation.',
        st['body']))
    story.append(Spacer(1,4))

    _sig_date = d_generated_at.split(' ')[0].replace('-', '/') if d_generated_at else '2026/01/01'
    _fn_base = d_filename.rsplit('.', 1)[0] if '.' in d_filename else d_filename
    _fn_stem = _fn_base[:32]
    sigma_rule = f'''title: {"/".join(d_families)} Persistence Mechanisms
id: aria-{"_".join(d_families[:1]).lower()}-persist-001
status: experimental
description: Detects {"/".join(d_families)} registry persistence and hidden scheduled task creation
author: ARIA v1.0 - OpenClaw
date: {_sig_date}
tags:
    - attack.persistence
    - attack.t1547.001
    - attack.t1053.005

detection:
    registry_run:
        EventID: 13
        TargetObject|contains: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
        Details|contains: '{_fn_stem[:20]}'
    scheduled_task:
        EventID: 4698
        TaskName|contains: '{_fn_stem[:20]}'
    process_inject:
        EventID: 8
        SourceImage|endswith: '{d_filename}'
    file_hash:
        EventID: 11
        Hashes|contains: '{d_md5}'
    condition: registry_run or scheduled_task or process_inject or file_hash

falsepositives:
    - None expected — strings are specific to this sample
level: critical'''

    sigma_tbl = Table([[Paragraph(sigma_rule,
                                   ParagraphStyle('sr', fontName='Courier', fontSize=6.5,
                                                   textColor=colors.HexColor('#222222'),
                                                   leading=10))
                         ]], colWidths=[W-1.1*inch])
    sigma_tbl.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#f8f8f8')),
        ('BOX',(0,0),(-1,-1),0.8,BORDER_DIM),
        ('LEFTPADDING',(0,0),(-1,-1),10),('RIGHTPADDING',(0,0),(-1,-1),10),
        ('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8),
    ]))
    story.append(sigma_tbl)
    story.append(Spacer(1,10))

    # Process/registry monitoring recommendations
    story.append(Paragraph('RECOMMENDED DETECTION POINTS', st['h2']))
    detect_data = [
        ['LAYER',     'INDICATOR',                                          'TOOL/METHOD'],
        ['Process',   f'{d_filename} spawning child processes',            'EDR process tree alert'],
        ['Registry',  f'Run key referencing {_fn_stem[:30]}',             'Sysmon Event ID 13'],
        ['File',      f'File hash match: MD5 {d_md5}',                    'File integrity / AV scan'],
        ['Network',   'Unexpected outbound HTTPS from endpoint',           'Firewall + proxy logs'],
        ['Scheduler', f'Hidden task referencing {_fn_stem[:25]}',         'Sysmon Event ID 4698'],
        ['Memory',    'Injected thread in system processes',               'EDR memory scanning'],
        ['File',      'YARA rule match on this sample SHA256',             'YARA on-access scan'],
        ['File',      'ssdeep fuzzy hash similarity score 70+',            'YARA/ssdeep variant hunt'],
    ]
    det_rows = []
    for i, row in enumerate(detect_data):
        if i == 0:
            det_rows.append([Paragraph(f'<b>{c}</b>', st['label']) for c in row])
        else:
            layer_col = {'Process':'#cc0000','Registry':'#555555','Network':'#cc0000',
                         'Scheduler':'#444444','Memory':'#cc0000','File':'#555555'}.get(row[0],'#333333')
            det_rows.append([
                Paragraph(f'<b><font color="{layer_col}">{row[0]}</font></b>',
                          ParagraphStyle('dl', fontName='Courier-Bold', fontSize=7.5,
                                         textColor=colors.HexColor(layer_col))),
                Paragraph(row[1], st['body']),
                Paragraph(row[2], st['mono']),
            ])
    det_table = Table(det_rows, colWidths=[0.75*inch, 3.5*inch, 2.95*inch])
    det_table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),BG_MID),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[BG_CARD,ROW_ALT]),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.3,BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('LEFTPADDING',(0,0),(-1,-1),6),('VALIGN',(0,0),(-1,-1),'TOP'),
    ]))
    story.append(det_table)

    # ── RAW EVIDENCE ───────────────────────────────────────────────────────────
    story.append(PageBreak())
    story += section_header('SECTION 5 — RAW TOOL EVIDENCE', st)

    # Ghidra results
    story.append(Paragraph('GHIDRA STATIC ANALYSIS', st['h2']))
    ghidra_stats = [
        [Paragraph('<b>TOTAL FUNCTIONS</b>',st['label']),
         Paragraph(f'{d_gh_funcs:,}',ParagraphStyle('gs',fontName='Courier-Bold',fontSize=14,
                                           textColor=ACCENT_CYAN,alignment=TA_CENTER)),
         Paragraph('<b>NAMED FUNCTIONS</b>',st['label']),
         Paragraph(f'{d_gh_named:,}',ParagraphStyle('gs2',fontName='Courier-Bold',fontSize=14,
                                           textColor=ACCENT_CYAN,alignment=TA_CENTER)),
         Paragraph('<b>TOTAL IMPORTS</b>',st['label']),
         Paragraph(f'{d_gh_imports:,}',ParagraphStyle('gs3',fontName='Courier-Bold',fontSize=14,
                                         textColor=ACCENT_RED,alignment=TA_CENTER))],
    ]
    gs_table = Table(ghidra_stats, colWidths=[1.2*inch,0.8*inch,1.2*inch,0.8*inch,1.0*inch,0.8*inch])
    gs_table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1),BG_CARD),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.3,BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),8),
        ('BOTTOMPADDING',(0,0),(-1,-1),8),
        ('ALIGN',(0,0),(-1,-1),'CENTER'),
        ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
    ]))
    story.append(gs_table)
    story.append(Spacer(1,6))

    story.append(Paragraph('SUSPICIOUS FUNCTION NAMES DETECTED BY GHIDRA (CRT/compiler symbols excluded):', st['h3']))
    suspicious_funcs = d_gh_suspicious or []
    # 3-column grid
    func_rows = []
    for i in range(0, len(suspicious_funcs), 3):
        row = suspicious_funcs[i:i+3]
        while len(row) < 3: row.append('')
        func_rows.append([
            Paragraph(f'<font color="#ef4444">⚠</font> {f}' if f else '',
                      ParagraphStyle('sf', fontName='Courier', fontSize=7,
                                     textColor=ACCENT_YLW))
            for f in row
        ])
    func_table = Table(func_rows, colWidths=[2.35*inch]*3)
    func_table.setStyle(TableStyle([
        ('ROWBACKGROUNDS',(0,0),(-1,-1),[BG_CARD, ROW_ALT]),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.3,BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),3),
        ('BOTTOMPADDING',(0,0),(-1,-1),3),
        ('LEFTPADDING',(0,0),(-1,-1),5),
    ]))
    story.append(func_table)
    story.append(Spacer(1,8))

    # YARA
    story.append(Paragraph('YARA SIGNATURE MATCHES', st['h2']))
    yara_hits = d_yara_hits or []
    # Classify each rule: findcrypt-style crypto detectors vs behavioral malware signatures
    _CRYPTO_DETECTOR_PATTERNS = [
        'Big_Numbers', 'Prime_Constants', 'SHA2', 'SHA1', 'SHA256', 'BLAKE2',
        'RijnDael', 'AES', 'RC4', 'CRC32', 'BASE64', 'MD5', 'XXTEA',
        'Blowfish', 'Camellia', 'Salsa20', 'ChaCha', 'CAST5',
    ]
    def _yara_category(rule_name):
        for pat in _CRYPTO_DETECTOR_PATTERNS:
            if pat.lower() in rule_name.lower():
                return 'Crypto constant detector — algorithm presence indicator'
        return 'Behavioral malware signature'
    yara_rows = [[
        Paragraph(f'<font color="#22c55e">✓ MATCH</font>',
                  ParagraphStyle('ym', fontName='Courier-Bold', fontSize=8,
                                 textColor=ACCENT_GRN)),
        Paragraph(y, ParagraphStyle('yn', fontName='Courier-Bold', fontSize=8,
                                     textColor=ACCENT_YLW)),
        Paragraph(_yara_category(y), st['mono']),
    ] for y in yara_hits]
    yara_table = Table(yara_rows, colWidths=[1.0*inch, 2.5*inch, 3.7*inch])
    yara_table.setStyle(TableStyle([
        ('ROWBACKGROUNDS',(0,0),(-1,-1),[BG_CARD, ROW_ALT]),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.3,BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),4),
        ('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('LEFTPADDING',(0,0),(-1,-1),6),
    ]))
    story.append(yara_table)
    story.append(Spacer(1,8))

    # FLOSS / CAPA summary
    story.append(Paragraph('FLOSS / CAPA SUMMARY', st['h2']))
    _capa_count = len(d_capa_caps) if d_capa_caps else 0
    _capa_note  = f'{_capa_count} capabilities mapped' if _capa_count else ('Binary packed — CAPA partially blind' if overlay_size else 'No capabilities matched')
    _vt_result  = f'{d_vt_str} detections' if d_vt_total > 0 else '0/0 — not in VT database'
    tool_summary = [
        ['TOOL', 'RESULT', 'NOTE'],
        ['FLOSS', 'String extraction complete', 'Static mode — obfuscated strings may be missed'],
        ['CAPA',  _capa_note, 'Packed binary may limit CAPA visibility'],
        ['DIE',   'Packer detection run', 'Detect-It-Easy analysis'],
        ['VT',    _vt_result, 'ARIA static evidence independent of VT result'],
    ]
    ts_rows = []
    for i, row in enumerate(tool_summary):
        if i == 0:
            ts_rows.append([Paragraph(f'<b>{c}</b>', st['label']) for c in row])
        else:
            note_col = ACCENT_YLW if 'packed' in row[1].lower() or '0/0' in row[1] else TEXT_GREY
            ts_rows.append([
                Paragraph(row[0], ParagraphStyle('tt', fontName='Courier-Bold', fontSize=8,
                                                  textColor=ACCENT_CYAN)),
                Paragraph(row[1], st['body']),
                Paragraph(row[2], ParagraphStyle('tn', fontName='Courier', fontSize=7,
                                                  textColor=TEXT_GREY)),
            ])
    ts_table = Table(ts_rows, colWidths=[0.7*inch, 3.5*inch, 3.0*inch])
    ts_table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),BG_MID),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[BG_CARD, ROW_ALT]),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.3,BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),4),
        ('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('LEFTPADDING',(0,0),(-1,-1),6),
        ('VALIGN',(0,0),(-1,-1),'TOP'),
    ]))
    story.append(ts_table)

    # ── REMEDIATION ROADMAP ───────────────────────────────────────────────────
    story.append(PageBreak())
    story += section_header('REMEDIATION ROADMAP', st)
    story.append(Paragraph(
        'Structured response timeline. Immediate actions are mandatory — '
        'short and long term items prevent recurrence.',
        st['body']))
    story.append(Spacer(1, 6))
    story.append(fig_to_rl(make_remediation_roadmap(), 7.0, 3.2))
    story.append(Spacer(1, 10))

    # Network block recommendations — extract from ARIA text
    import re as _re_net
    story.append(Paragraph('NETWORK INDICATORS — FIREWALL BLOCK LIST', st['h2']))
    # Extract domains — then filter out system DLLs, EXEs, and other non-network artifacts
    _raw_domains = list(dict.fromkeys(_re_net.findall(
        r'(?:api\.|www\.)[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}|[a-zA-Z0-9_-]+\.[a-zA-Z]{2,4}(?:/[^\s]*)?',
        d_aria_text)))
    _SYSTEM_EXTS = _re_net.compile(
        r'\.(dll|exe|sys|ocx|drv|dat|db|bin|tmp|log|cfg|ini|bat|cmd|ps1|vbs|js|json|xml|txt|pdb|lib|obj|pem|cer|crt|pfx)$',
        _re_net.IGNORECASE)
    _FAKE_TLDS = _re_net.compile(
        r'\.(time|size|type|name|data|base|hash|key|val|str|int|hex|raw|pe|md5|sha|crc|rva|off|sec|hdr|img|map|rtti|comm|syst|util|func|proc|list|node|obj|cls|ptr|ref|impl|core|unit|pack|math)$',
        _re_net.IGNORECASE)
    _KNOWN_FALSE_POSITIVES = {'N/A', 'PE32', 'PE64', 'MED', 'HIGH', 'LOW', 'v1.0',
                               'pe.time', 'key4.db', 'places.sqlite'}
    # Real domains are lowercase — CamelCase or UPPER.Mixed strings are PE/C++ artifacts
    _camel_case = _re_net.compile(r'[A-Z][a-z]+\.[A-Z]')
    _upper_dot = _re_net.compile(r'^[A-Z]{2,}\.')
    _net_domains = [
        d for d in _raw_domains
        if not _SYSTEM_EXTS.search(d)
        and not _FAKE_TLDS.search(d)
        and not _camel_case.match(d)
        and not _upper_dot.match(d)
        and d not in _KNOWN_FALSE_POSITIVES
        and '.' in d
        and len(d) > 4
        and not d.startswith('0x')
    ][:8]
    _net_ips = list(dict.fromkeys(_re_net.findall(
        r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b', d_aria_text)))[:5]
    _net_ioc_rows = [['INDICATOR', 'TYPE', 'ACTION', 'PRIORITY', 'REASON']]
    for _dom in _net_domains[:4]:
        _dom_clean = _dom.replace('hxxp','http').replace('[.]','.')
        _net_ioc_rows.append([_dom_clean, 'DOMAIN', 'BLOCK OUTBOUND', 'HIGH', 'Extracted from ARIA analysis — potential C2'])
    for _ip in _net_ips[:3]:
        _net_ioc_rows.append([_ip, 'IP/CIDR', 'BLOCK OUTBOUND', 'HIGH', 'Extracted from ARIA analysis'])
    if len(_net_ioc_rows) == 1:
        _net_ioc_rows.append(['(No network IOCs extracted)', 'N/A', 'N/A', 'N/A', 'Run dynamic analysis to identify C2'])
    net_iocs = _net_ioc_rows
    net_rows = []
    for i, row in enumerate(net_iocs):
        if i == 0:
            net_rows.append([Paragraph(f'<b>{c}</b>', st['label']) for c in row])
        else:
            pri_col = '#cc0000' if row[3] == 'CRITICAL' else '#555555'
            net_rows.append([
                Paragraph(row[0], ParagraphStyle('nv', fontName='Courier-Bold', fontSize=7.5,
                                                  textColor=colors.HexColor('#cc0000'))),
                Paragraph(row[1], st['mono']),
                Paragraph(f'<b><font color="#cc0000">{row[2]}</font></b>',
                          ParagraphStyle('na', fontName='Courier-Bold', fontSize=7.5,
                                         textColor=ACCENT_RED)),
                Paragraph(f'<b><font color="{pri_col}">{row[3]}</font></b>',
                          ParagraphStyle('np', fontName='Courier-Bold', fontSize=7.5,
                                         textColor=colors.HexColor(pri_col))),
                Paragraph(row[4], st['mono']),
            ])
    net_table = Table(net_rows, colWidths=[1.35*inch, 0.65*inch, 1.1*inch, 0.75*inch, 3.35*inch])
    net_table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),BG_MID),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[BG_CARD, ROW_ALT]),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.3,BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('LEFTPADDING',(0,0),(-1,-1),6),('VALIGN',(0,0),(-1,-1),'MIDDLE'),
    ]))
    story.append(net_table)
    story.append(Spacer(1, 10))

    # Dynamic Analysis warning box
    story.append(Paragraph('⚠  DYNAMIC ANALYSIS REQUIRED', st['warn']))
    _dyn_reason = ''
    if overlay_size:
        _dyn_reason = f'encrypted in a {overlay_mb} overlay and decrypted at runtime'
        if tls_count: _dyn_reason += f' via {tls_count} TLS callback{"s" if tls_count!=1 else ""}'
    elif tls_count:
        _dyn_reason = f'protected by {tls_count} TLS callback{"s" if tls_count!=1 else ""} executing before main()'
    else:
        _dyn_reason = 'obfuscated in ways that limit static visibility'
    dyn_text = [
        Paragraph(
            f'CAPA returned {_capa_count if _capa_count else "limited"} matches because the payload is '
            f'{_dyn_reason}. '
            'Static analysis may be <b>partially blind</b> to the actual capabilities of this sample.',
            st['body']),
        Spacer(1, 4),
        Paragraph('<b>RECOMMENDED SANDBOX PLATFORMS:</b>', st['h3']),
        Paragraph('• Any.run (interactive) — observe live C2 beacon and process injection', st['bullet']),
        Paragraph('• Cuckoo Sandbox (self-hosted) — full memory dump and network PCAP', st['bullet']),
        Paragraph('• Joe Sandbox — automated MITRE ATT&CK mapping from dynamic trace', st['bullet']),
        Spacer(1, 4),
        Paragraph('<b>PRIORITY OBJECTIVES FOR DYNAMIC RUN:</b>', st['h3']),
        Paragraph('• Capture decrypted payload in memory — unpack and re-analyze with CAPA', st['bullet']),
        Paragraph('• Record all network traffic — extract C2 endpoints and exfil content', st['bullet']),
        Paragraph('• Observe TLS callback / entry point execution — map decryption routine', st['bullet']),
    ]
    dyn_box = Table([dyn_text], colWidths=[W - 1.1*inch])
    dyn_box.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1),colors.HexColor('#fff8f8')),
        ('BOX',(0,0),(-1,-1),1.2,ACCENT_RED),
        ('LEFTPADDING',(0,0),(-1,-1),12),('RIGHTPADDING',(0,0),(-1,-1),12),
        ('TOPPADDING',(0,0),(-1,-1),10),('BOTTOMPADDING',(0,0),(-1,-1),10),
    ]))
    story.append(dyn_box)

    # ── ANALYST NOTES ─────────────────────────────────────────────────────────
    story.append(PageBreak())
    story += section_header('ANALYST NOTES', st)

    analyst_note_text = d_analyst_notes if d_analyst_notes else (
        'No analyst notes were submitted with this sample. '
        'To include analyst observations, use the Notes field in the ARIA submission '
        'interface prior to generating this report.'
    )

    story.append(HRFlowable(width='100%', thickness=1, color=BORDER_DIM))
    story.append(Paragraph('SUBMITTED ANALYST ANNOTATION', st['h2']))
    story.append(Spacer(1, 4))
    story.append(Paragraph(analyst_note_text,
                            ParagraphStyle('note', fontName='Courier', fontSize=8,
                                           textColor=colors.HexColor('#555555'), leading=13)))
    story.append(Spacer(1, 10))
    story.append(Paragraph('ANALYST: ___________________________    DATE: 2026-03-12', st['mono']))
    story.append(Spacer(1, 4))
    story.append(Paragraph('SIGNATURE: _______________________   ROLE: _____________________', st['mono']))
    story.append(HRFlowable(width='100%', thickness=1, color=BORDER_DIM))
    story.append(Spacer(1, 16))

    # ── CHAIN OF CUSTODY ──────────────────────────────────────────────────────
    story += section_header('CHAIN OF CUSTODY  &  REPORT CERTIFICATION', st)

    coc_data = [
        ['FIELD', 'VALUE'],
        ['Report Generated By',   'ARIA v1.0 — Automated Reverse Engineering & Intelligence Agent'],
        ['Analysis Platform',     'OpenClaw Malware Analysis Platform'],
        ['Generation Timestamp',  d_generated_at],
        ['Sample Received',       'Via OpenClaw submission interface'],
        ['Sample SHA256',         d_sha256],
        ['Sample MD5',            d_md5],
        ['Analysis Type',         'Static — PE analysis, YARA, Ghidra, FLOSS, CAPA, VirusTotal'],
        ['Dynamic Analysis',      'NOT PERFORMED — see Dynamic Analysis section'],
        ['Classification',        'CONFIDENTIAL — Authorized Recipients Only'],
        ['Report Version',        'v1.0 — Initial Analysis'],
        ['Analyst Override',      'NONE — ARIA autonomous verdict'],
    ]
    coc_rows = []
    for i, row in enumerate(coc_data):
        if i == 0:
            coc_rows.append([Paragraph(f'<b>{c}</b>', st['label']) for c in row])
        else:
            coc_rows.append([
                Paragraph(row[0], st['label']),
                Paragraph(row[1], st['body']),
            ])
    coc_table = Table(coc_rows, colWidths=[1.8*inch, 5.4*inch])
    coc_table.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),BG_MID),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[BG_CARD, ROW_ALT]),
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.3,BORDER_DIM),
        ('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('LEFTPADDING',(0,0),(-1,-1),6),('VALIGN',(0,0),(-1,-1),'TOP'),
    ]))
    story.append(coc_table)
    story.append(Spacer(1, 14))

    # Signature block
    sig_data = [
        # Header row
        [Paragraph('REVIEWING ANALYST', st['label']),
         Paragraph('APPROVING AUTHORITY', st['label']),
         Paragraph('LEGAL / COMPLIANCE', st['label'])],
        # Spacer row
        [Spacer(1, 16), Spacer(1, 16), Spacer(1, 16)],
        # Signature row
        [Paragraph('Signature: ___________________', st['mono']),
         Paragraph('Signature: ___________________', st['mono']),
         Paragraph('Signature: ___________________', st['mono'])],
        [Paragraph('Print Name: _________________', st['mono']),
         Paragraph('Print Name: _________________', st['mono']),
         Paragraph('Print Name: _________________', st['mono'])],
        [Paragraph('Date: _______________________', st['mono']),
         Paragraph('Date: _______________________', st['mono']),
         Paragraph('Date: _______________________', st['mono'])],
    ]
    sig_table = Table(sig_data, colWidths=[2.4*inch, 2.4*inch, 2.4*inch])
    sig_table.setStyle(TableStyle([
        ('BOX',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('INNERGRID',(0,0),(-1,-1),0.5,BORDER_DIM),
        ('BACKGROUND',(0,0),(-1,-1),BG_CARD),
        ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),
        ('LEFTPADDING',(0,0),(-1,-1),8),('RIGHTPADDING',(0,0),(-1,-1),8),
        ('VALIGN',(0,0),(-1,-1),'MIDDLE'),
    ]))
    story.append(sig_table)
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        'This report was generated automatically by ARIA. All findings should be reviewed '
        'by a qualified security analyst before use in legal, regulatory, or insurance proceedings. '
        'ARIA analysis is based on static indicators only unless dynamic analysis is noted above.',
        ParagraphStyle('disc', fontName='Courier', fontSize=6.5, textColor=TEXT_GREY,
                        leading=10, alignment=TA_CENTER)))

    # ── BUILD ──────────────────────────────────────────────────────────────────
    page_cb = ARIACanvas()

    def first_page(c, d):
        cover_callback(c, d)

    def later_pages(c, d):
        page_cb(c, d)

    doc.build(story, onFirstPage=first_page, onLaterPages=later_pages)
    print(f'Report written to {out_path}')

if __name__ == '__main__':
    build_report('/mnt/user-data/outputs/ARIA_Report_v2.pdf')


# ══════════════════════════════════════════════════════════════════════════════
# DYNAMIC ENTRY POINT — called from api.py
# ══════════════════════════════════════════════════════════════════════════════
def build_report_from_data(data, out_path):
    """Maps actual OpenClaw pipeline JSON to build_report kwargs."""
    import re, datetime

    hashes      = data.get('hashes', {})
    md5         = hashes.get('md5', 'N/A')
    sha1        = hashes.get('sha1', 'N/A')
    sha256      = hashes.get('sha256', 'N/A')
    ssdeep_hash = hashes.get('ssdeep', 'N/A')

    pe          = data.get('pe_info', {})
    sections    = pe.get('sections', [])
    pe_imports_raw = pe.get('imports', [])
    compile_time   = pe.get('compile_time', 'N/A')
    architecture   = pe.get('machine', 'N/A')
    imphash        = pe.get('imphash', 'N/A')

    overlay_raw = pe.get('overlay', {})
    overlay = {
        'offset':  overlay_raw.get('offset', 'N/A') if isinstance(overlay_raw, dict) else 'N/A',
        'size':    overlay_raw.get('size', 0)        if isinstance(overlay_raw, dict) else 0,
        'entropy': overlay_raw.get('entropy', 0)     if isinstance(overlay_raw, dict) else 0,
    }

    tls_raw  = pe.get('tls_callbacks', {})
    tls_cbs  = tls_raw.get('callbacks', []) if isinstance(tls_raw, dict) else []

    rich_raw     = pe.get('rich_header', {})
    rich_header  = rich_raw.get('present', False) if isinstance(rich_raw, dict) else bool(rich_raw)
    auth_raw     = pe.get('authenticode', {})
    authenticode = auth_raw.get('present', False) if isinstance(auth_raw, dict) else bool(auth_raw)

    section_names     = [s.get('name', '?') for s in sections]
    section_entropies = [float(s.get('entropy', 0)) for s in sections]

    susp_keywords = {
        'GetAsyncKeyState':        ('USER32',   'Keylogging'),
        'GetClipboardData':        ('USER32',   'Clipboard theft'),
        'BlockInput':              ('USER32',   'Locks keyboard/mouse'),
        'SetWindowsHookExA':       ('USER32',   'Global input hook'),
        'SetWindowsHookExW':       ('USER32',   'Global input hook'),
        'IsDebuggerPresent':       ('KERNEL32', 'Anti-debug check'),
        'GetTickCount':            ('KERNEL32', 'Timing sandbox evasion'),
        'OpenProcess':             ('KERNEL32', 'Process injection'),
        'WinExec':                 ('KERNEL32', 'Executes commands'),
        'CreateToolhelp32Snapshot':('KERNEL32', 'Process enumeration'),
        'Sleep':                   ('KERNEL32', 'Sandbox evasion delay'),
        'VirtualAllocEx':          ('KERNEL32', 'Remote memory alloc'),
        'WriteProcessMemory':      ('KERNEL32', 'Process memory write'),
        'CreateRemoteThread':      ('KERNEL32', 'Remote thread injection'),
        'CryptEncrypt':            ('ADVAPI32', 'Data encryption'),
        'CryptCreateHash':         ('ADVAPI32', 'Hash computation'),
        'CryptDeriveKey':          ('ADVAPI32', 'Key derivation'),
        'CryptGenRandom':          ('ADVAPI32', 'Crypto random'),
        'RegSetValueExA':          ('ADVAPI32', 'Registry persistence'),
        'RegSetValueExW':          ('ADVAPI32', 'Registry persistence'),
        'RegOpenKeyExA':           ('ADVAPI32', 'Registry access'),
        'WinHttpConnect':          ('WINHTTP',  'C2 connection'),
        'WinHttpSendRequest':      ('WINHTTP',  'C2 request'),
        'BitBlt':                  ('GDI32',    'Screen capture'),
        'CreateCompatibleBitmap':  ('GDI32',    'Screenshot bitmap'),
    }
    suspicious_imports = []
    for dll_entry in pe_imports_raw:
        dll_name  = dll_entry.get('dll', '').upper().replace('.DLL','')
        functions = dll_entry.get('functions', [])
        for fn in functions:
            if fn in susp_keywords:
                _, sig = susp_keywords[fn]
                suspicious_imports.append((dll_name, fn, sig))

    ghidra      = data.get('ghidra', {})
    gh_funcs    = ghidra.get('total_functions', 0)
    gh_named    = ghidra.get('named_functions', 0)
    gh_imports  = ghidra.get('total_imports', 0)
    gh_suspicious = ghidra.get('suspicious_functions', [])

    yara_hits = []
    for y in data.get('yara_matches', []):
        rule = y.split(' ')[0] if isinstance(y, str) else y.get('rule', str(y))
        yara_hits.append(rule)

    vt           = data.get('virustotal', {})
    vt_found     = vt.get('found', False)
    vt_malicious = vt.get('malicious', 0)
    vt_suspicious= vt.get('suspicious', 0)
    vt_total     = vt.get('total', 0)
    if vt_total == 0:
        vt_total = (vt.get('malicious', 0) + vt.get('suspicious', 0) +
                    vt.get('undetected', 0) + vt.get('harmless', 0))
    vt_str = f'{vt_malicious}/{vt_total}' if vt_found or vt_total > 0 else '0/0'

    score   = int(data.get('confidence_score') or 0)
    verdict = (data.get('verdict') or 'UNKNOWN').upper()

    if score == 0 and (suspicious_imports or gh_suspicious or yara_hits):
        try:
            import sys; sys.path.insert(0,'/sandbox')
            from api import compute_confidence_score
            results = {'pe_info': pe, 'yara': [{'rule': r} for r in yara_hits],
                       'capa': data.get('capa', {}), 'virustotal': vt, 'ghidra': ghidra}
            score_data = compute_confidence_score(results)
            score   = score_data.get('score', 0)
            verdict = score_data.get('verdict', verdict)
        except Exception:
            score = min(100, len(suspicious_imports)*4 + len(yara_hits)*5 + (20 if gh_suspicious else 0))
            if score >= 70:   verdict = 'MALICIOUS'
            elif score >= 40: verdict = 'SUSPICIOUS'
            else:             verdict = 'BENIGN'

    if verdict == 'UNKNOWN':
        import re as _re
        _at = (data.get('aria', {}).get('full_response') or
               data.get('aria', {}).get('technical_report') or '')
        m = _re.search(r'VERDICT[:\*\s]+(MALICIOUS|SUSPICIOUS|BENIGN)', _at, _re.IGNORECASE)
        if m:
            verdict = m.group(1).upper()
            if not score:
                score = 85 if verdict == 'MALICIOUS' else 50

    aria        = data.get('aria', {})
    aria_text   = (aria.get('full_response') or aria.get('technical_report') or
                   aria.get('executive_report') or data.get('aria_report', ''))

    filename    = data.get('filename', 'unknown.exe')
    size_bytes  = data.get('size', hashes.get('size_bytes', 0))
    file_size   = f'{size_bytes/1024/1024:.2f} MB' if size_bytes else 'N/A'
    ft          = data.get('file_type', {})
    file_type   = ft.get('description', ft.get('mime', 'N/A')) if isinstance(ft, dict) else str(ft)
    generated_at= data.get('generated_at', datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'))
    analyst_notes = data.get('analyst_notes', '')

    # Family detection — require strong attribution context, not incidental mention
    # "ransom" alone fires on "used in ransomware campaigns" — require "ransomware" as noun or ransomware-specific functions
    family_map = {
        'RAT':         [r'remote.access.trojan', r'\brat\b(?!io)', r'remote administration tool'],
        'INFOSTEALER': [r'info.?stealer', r'credential.stealer', r'infostealer'],
        'KEYLOGGER':   [r'keylog', r'keystroke.logger'],
        'RANSOMWARE':  [r'ransom.note', r'encrypt.and.delete', r'encryptfile',
                        r'(?:this (?:sample|file|malware|binary)|it)\s+is\s+(?:a\s+)?ransomware',
                        r'(?:identified|classified|categorized|detected)\s+as\s+(?:a\s+)?ransomware',
                        r'family[:\s]+ransomware'],
        'BACKDOOR':    [r'\bbackdoor\b'],
        'DROPPER':     [r'(?:is|acts? as|classified as|identified as) a dropper', r'dropper family', r'dropper malware'],
        'SPYWARE':     [r'\bspyware\b'],
        'BANKER':      [r'banking.trojan', r'\bbanker\b'],
    }
    aria_lower = aria_text.lower()
    families = [fam for fam, kws in family_map.items() if any(re.search(kw, aria_lower) for kw in kws)]
    if not families:
        if any('keylog' in f.lower() or 'keystroke' in f.lower() for f in gh_suspicious): families.append('KEYLOGGER')
        if any('inject' in f.lower() for f in gh_suspicious): families.append('RAT')
        if any('telegram' in f.lower() for f in gh_suspicious): families.append('INFOSTEALER')
    # All RATs are backdoors by definition — auto-tag for consistency
    if 'RAT' in families and 'BACKDOOR' not in families:
        families.append('BACKDOOR')
    if not families: families = ['UNKNOWN']

    threat_type = '/'.join(families)
    for line in aria_text.split('\n'):
        ll = line.lower()
        # Only match explicit "threat type:" label — not "machine type:", "file type:", "pe type:" etc.
        if ll.strip().startswith('threat type') and ':' in ll:
            parts = line.split(':', 1)
            if len(parts) > 1 and len(parts[1].strip()) > 2:
                threat_type = parts[1].strip().strip('*').strip()[:80]
                break

    verdict_color = {'MALICIOUS':'#cc0000','SUSPICIOUS':'#cc6600','BENIGN':'#007700'}.get(verdict,'#555555')
    score_color   = '#cc0000' if score >= 70 else ('#cc6600' if score >= 40 else '#007700')

    all_funcs_lower = ' '.join(gh_suspicious).lower() + ' ' + aria_lower
    cap_checks = [
        ('Keylogging',  ['keylog','getasynckey','keystroke']),
        ('C2 Comms',    ['telegram','c2','winhttp','beacon']),
        ('Persistence', ['persist','registry run','scheduled task','setuppers']),
        ('Injection',   ['inject','hollow','createremotethread']),
        ('Evasion',     ['evasion','anti.debug','sandbox','obfuscat','stealth']),
        ('Encryption',  ['encrypt','aes','cryptencrypt','zipcrypto']),
        ('Exfil',       ['exfil','upload','steal']),
        ('Recon',       ['recon','enumerat','snapshot','ipify']),
        ('Screenshot',  ['screenshot','camera','capture','bitblt']),
        ('Ransomware',  ['encryptanddelete','encryptfile','ransomnote',r'\.onion']),
    ]
    radar_caps = {}
    for cap, kws in cap_checks:
        v = sum(3 for kw in kws if re.search(kw, all_funcs_lower))
        if v > 0: radar_caps[cap] = min(10, v)

    # Boost radar scores from confirmed suspicious imports — direct API import = CONFIRMED (≥7)
    _import_radar_boost = {
        'SetWindowsHookExA': 'Keylogging',  'SetWindowsHookExW': 'Keylogging',
        'GetAsyncKeyState':  'Keylogging',  'GetClipboardData':  'Keylogging',
        'WinHttpConnect':    'C2 Comms',    'WinHttpSendRequest': 'C2 Comms',
        'WriteProcessMemory':'Injection',   'CreateRemoteThread': 'Injection',
        'VirtualAllocEx':    'Injection',   'OpenProcess':        'Injection',
        'IsDebuggerPresent': 'Evasion',     'Sleep':              'Evasion',
        'GetTickCount':      'Evasion',
        'CryptEncrypt':      'Encryption',  'CryptGenRandom':     'Encryption',
        'CreateToolhelp32Snapshot': 'Recon','OpenProcess':        'Recon',
        'BitBlt':            'Screenshot',  'CreateCompatibleBitmap': 'Screenshot',
    }
    for _, fn, _ in suspicious_imports:
        cap = _import_radar_boost.get(fn)
        if cap:
            radar_caps[cap] = max(radar_caps.get(cap, 0), 9)  # 9 = CONFIRMED threshold

    capa_caps = data.get('capa', {}).get('capabilities', [])
    breakdown = data.get('confidence_breakdown', [])

    build_report(
        out_path,
        d_filename=filename, d_md5=md5, d_sha1=sha1, d_sha256=sha256,
        d_ssdeep=ssdeep_hash, d_imphash=imphash,
        d_score=score, d_verdict=verdict,
        d_verdict_color=verdict_color, d_score_color=score_color,
        d_generated_at=generated_at, d_file_size=file_size, d_file_type=file_type,
        d_vt_str=vt_str, d_vt_malicious=vt_malicious, d_vt_suspicious=vt_suspicious, d_vt_total=vt_total,
        d_compile_time=compile_time, d_architecture=architecture,
        d_sections=sections, d_section_names=section_names, d_section_entropies=section_entropies,
        d_pe_imports=pe_imports_raw, d_tls_cbs=tls_cbs, d_overlay=overlay,
        d_rich_header=rich_header, d_authenticode=authenticode,
        d_gh_funcs=gh_funcs, d_gh_named=gh_named, d_gh_imports=gh_imports,
        d_gh_suspicious=gh_suspicious, d_yara_hits=yara_hits, d_capa_caps=capa_caps,
        d_suspicious_imports=suspicious_imports, d_families=families,
        d_threat_type=threat_type, d_aria_text=aria_text, d_analyst_notes=analyst_notes,
        d_radar_caps=radar_caps, d_breakdown=breakdown,
    )

