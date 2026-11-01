"""
KubeGuard Report Generator
Generates standalone, executive-ready HTML audit reports with high-contrast styling and remediation blueprints.
"""

from datetime import datetime
from typing import Optional
from kube_guard.models import ScanResult, Severity
from kube_guard.scoring import get_risk_color, SCORING_DISCLAIMER


SEVERITY_BADGE_COLORS = {
    Severity.CRITICAL: {"bg": "#450a0a", "text": "#f87171", "border": "#dc2626"},
    Severity.HIGH: {"bg": "#431407", "text": "#fb923c", "border": "#ea580c"},
    Severity.MEDIUM: {"bg": "#422006", "text": "#facc15", "border": "#ca8a04"},
    Severity.LOW: {"bg": "#172554", "text": "#60a5fa", "border": "#2563eb"},
    Severity.INFO: {"bg": "#1e293b", "text": "#94a3b8", "border": "#475569"},
}


def generate_html_report(result: ScanResult, report_title: str = "KubeGuard Security Audit Report") -> str:
    """Generate a self-contained, beautifully styled HTML security report."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    risk_color = get_risk_color(result.risk_level)

    findings_html_list = []
    # Sort findings by severity priority
    order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    sorted_findings = sorted(result.findings, key=lambda f: order.get(f.severity, 99))

    for idx, f in enumerate(sorted_findings, 1):
        colors = SEVERITY_BADGE_COLORS.get(f.severity, {"bg": "#333", "text": "#fff", "border": "#555"})
        remediation_code_block = ""
        if f.remediation_yaml:
            remediation_code_block = f"""
            <div class="code-box">
                <div class="code-title">Suggested Remediation Snippet</div>
                <pre><code>{f.remediation_yaml}</code></pre>
            </div>
            """

        finding_card = f"""
        <div class="finding-card severity-{f.severity.value.lower()}">
            <div class="finding-header">
                <div class="finding-meta">
                    <span class="badge" style="background:{colors['bg']}; color:{colors['text']}; border: 1px solid {colors['border']};">
                        {f.severity.value}
                    </span>
                    <span class="rule-id">{f.rule_id}</span>
                    <span class="category-tag">{f.category.value}</span>
                </div>
                <h3 class="finding-title">#{idx}. {f.title}</h3>
            </div>
            <div class="finding-body">
                <div class="info-row">
                    <span class="label">Resource:</span>
                    <span class="value code-inline">{f.resource}</span>
                </div>
                <div class="info-row">
                    <span class="label">Location:</span>
                    <span class="value">{f.file} &rarr; <code>{f.location or 'N/A'}</code></span>
                </div>
                <div class="info-row">
                    <span class="label">Evidence:</span>
                    <div class="evidence-box"><code>{f.evidence}</code></div>
                </div>
                <div class="info-row">
                    <span class="label">Impact:</span>
                    <p class="impact-text">{f.impact}</p>
                </div>
                <div class="info-row">
                    <span class="label">Remediation:</span>
                    <p class="remediation-text">{f.remediation}</p>
                </div>
                {remediation_code_block}
            </div>
        </div>
        """
        findings_html_list.append(finding_card)

    findings_content = "\n".join(findings_html_list) if findings_html_list else "<p class='no-findings'>No security misconfigurations identified. Excellent baseline posture!</p>"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_title}</title>
    <style>
        :root {{
            --bg-dark: #0b0f19;
            --card-bg: #111827;
            --border-color: #1f2937;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent-cyan: #06b6d4;
            --crit: #ef4444;
            --high: #f97316;
            --med: #eab308;
            --low: #3b82f6;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            line-height: 1.6;
            padding: 30px 20px;
        }}
        .container {{
            max-width: 1080px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 24px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 15px;
        }}
        .brand-title {{
            font-size: 28px;
            font-weight: 800;
            letter-spacing: -0.5px;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .brand-title span {{
            color: var(--accent-cyan);
        }}
        .brand-subtitle {{
            font-size: 14px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 4px;
        }}
        .report-meta {{
            text-align: right;
            font-size: 13px;
            color: var(--text-muted);
        }}
        .exec-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .summary-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .score-value {{
            font-size: 42px;
            font-weight: 800;
            line-height: 1;
            margin: 10px 0;
        }}
        .risk-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-weight: 700;
            font-size: 14px;
            letter-spacing: 0.5px;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 32px;
        }}
        .metric-box {{
            background: var(--card-bg);
            border-radius: 8px;
            padding: 14px;
            text-align: center;
            border-left: 4px solid var(--border-color);
        }}
        .metric-box.crit {{ border-left-color: var(--crit); }}
        .metric-box.high {{ border-left-color: var(--high); }}
        .metric-box.med {{ border-left-color: var(--med); }}
        .metric-box.low {{ border-left-color: var(--low); }}
        .metric-number {{
            font-size: 26px;
            font-weight: 700;
            margin-top: 4px;
        }}
        .section-header {{
            font-size: 20px;
            font-weight: 700;
            margin: 32px 0 16px 0;
            color: #ffffff;
            border-left: 4px solid var(--accent-cyan);
            padding-left: 12px;
        }}
        .finding-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            transition: transform 0.15s ease;
        }}
        .finding-meta {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 8px;
        }}
        .badge {{
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            padding: 2px 8px;
            border-radius: 4px;
            letter-spacing: 0.5px;
        }}
        .rule-id {{
            font-family: monospace;
            font-size: 13px;
            color: var(--accent-cyan);
            font-weight: 600;
        }}
        .category-tag {{
            font-size: 12px;
            color: var(--text-muted);
            background: #1e293b;
            padding: 2px 8px;
            border-radius: 4px;
        }}
        .finding-title {{
            font-size: 17px;
            font-weight: 700;
            margin-bottom: 12px;
            color: #fff;
        }}
        .info-row {{
            margin-bottom: 10px;
        }}
        .label {{
            display: inline-block;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            width: 110px;
        }}
        .value {{
            font-size: 14px;
            color: #e2e8f0;
        }}
        .code-inline {{
            font-family: monospace;
            background: #1e293b;
            padding: 2px 6px;
            border-radius: 4px;
            color: #38bdf8;
        }}
        .evidence-box {{
            display: inline-block;
            background: #0f172a;
            border: 1px solid #334155;
            padding: 6px 12px;
            border-radius: 4px;
            color: #f87171;
            font-family: monospace;
            font-size: 13px;
            margin-top: 4px;
        }}
        .impact-text {{
            display: inline;
            color: #fca5a5;
            font-size: 14px;
        }}
        .remediation-text {{
            display: inline;
            color: #86efac;
            font-size: 14px;
        }}
        .code-box {{
            background: #0a0e17;
            border: 1px solid #1f2937;
            border-radius: 6px;
            margin-top: 12px;
            overflow: hidden;
        }}
        .code-title {{
            background: #111827;
            padding: 6px 12px;
            font-size: 11px;
            text-transform: uppercase;
            color: #9ca3af;
            font-weight: 700;
            border-bottom: 1px solid #1f2937;
        }}
        pre {{
            padding: 12px;
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace;
            font-size: 13px;
            color: #38bdf8;
            overflow-x: auto;
        }}
        .disclaimer-box {{
            background: #18181b;
            border: 1px solid #27272a;
            border-radius: 6px;
            padding: 16px;
            margin-top: 40px;
            font-size: 12px;
            color: #71717a;
            text-align: center;
        }}
        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .summary-card, .metric-box, .finding-card, .code-box {{ background: #fff; border-color: #ccc; }}
            .brand-title, .finding-title, .section-header {{ color: #000; }}
            pre {{ background: #f8f8f8; color: #111; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1 class="brand-title">&#128737;&#65039; Kube<span>Guard</span></h1>
                <div class="brand-subtitle">Container &amp; Kubernetes Security Auditor</div>
            </div>
            <div class="report-meta">
                <div>Generated: <strong>{now_str}</strong></div>
                <div>Audit Type: <strong>Static Configuration Analysis</strong></div>
            </div>
        </header>

        <div class="exec-summary">
            <div class="summary-card">
                <div class="label">Security Score</div>
                <div class="score-value" style="color: {risk_color};">{result.score} <span style="font-size:20px; color:#6b7280;">/ 100</span></div>
                <div class="risk-badge" style="background: {risk_color}22; color: {risk_color}; border: 1px solid {risk_color};">
                    {result.risk_level}
                </div>
            </div>
            <div class="summary-card">
                <div class="label">Scope Overview</div>
                <div style="margin-top: 12px; text-align: left; padding: 0 10px;">
                    <div style="margin-bottom: 6px; font-size: 14px;"><strong>Files Scanned:</strong> {len(result.files_scanned)}</div>
                    <div style="margin-bottom: 6px; font-size: 14px;"><strong>Resources Scanned:</strong> {result.resources_scanned}</div>
                    <div style="font-size: 14px;"><strong>Total Issues:</strong> {result.total_findings}</div>
                </div>
            </div>
        </div>

        <div class="metrics-grid">
            <div class="metric-box crit">
                <div class="label">Critical</div>
                <div class="metric-number" style="color: var(--crit);">{result.critical_count}</div>
            </div>
            <div class="metric-box high">
                <div class="label">High</div>
                <div class="metric-number" style="color: var(--high);">{result.high_count}</div>
            </div>
            <div class="metric-box med">
                <div class="label">Medium</div>
                <div class="metric-number" style="color: var(--med);">{result.medium_count}</div>
            </div>
            <div class="metric-box low">
                <div class="label">Low</div>
                <div class="metric-number" style="color: var(--low);">{result.low_count}</div>
            </div>
        </div>

        <h2 class="section-header">Detailed Security Findings ({len(sorted_findings)})</h2>
        <div class="findings-list">
            {findings_content}
        </div>

        <div class="disclaimer-box">
            <strong>Important Security Disclaimer:</strong> {SCORING_DISCLAIMER}
            <br>
            This report represents static configuration analysis and does not constitute a complete Kubernetes security assessment.
            In production environments, complement static auditing with image vulnerability scanning (e.g., Trivy), runtime threat detection (e.g., Falco), and cluster CIS benchmark compliance checks (e.g., kube-bench).
        </div>
    </div>
</body>
</html>
"""
    return html
