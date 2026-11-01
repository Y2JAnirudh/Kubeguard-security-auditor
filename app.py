"""
KubeGuard: Container & Kubernetes Security Auditor
Main Streamlit Application Dashboard
"""

import sys
from pathlib import Path
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from kube_guard.models import Finding, ScanResult, Severity, Category
from kube_guard.scanner import scan_files, scan_directory, scan_content
from kube_guard.scoring import get_risk_color, SCORING_DISCLAIMER
from kube_guard.report import generate_html_report


# ============================================================================
# PAGE CONFIGURATION & DARK SECURITY THEME
# ============================================================================

st.set_page_config(
    page_title="KubeGuard - Container & Kubernetes Security Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
    /* Dark Cybersecurity Dashboard Theme */
    .stApp {
        background-color: #0b0f19;
        color: #f3f4f6;
    }
    
    /* Header & Branding */
    .brand-container {
        padding: 1.2rem 1.5rem;
        background: linear-gradient(135deg, #111827 0%, #1e1b4b 100%);
        border: 1px solid #312e81;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    .brand-title {
        font-size: 2.2rem;
        font-weight: 800;
        letter-spacing: -0.5px;
        color: #ffffff;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }
    .brand-title span {
        color: #38bdf8;
    }
    .brand-subtitle {
        color: #94a3b8;
        font-size: 0.95rem;
        font-weight: 500;
        letter-spacing: 0.5px;
        margin-top: 0.25rem;
    }
    
    /* Metric Score Card */
    .score-card {
        background: #111827;
        border-radius: 10px;
        padding: 1.25rem;
        border: 1px solid #1f2937;
        text-align: center;
    }
    .score-number {
        font-size: 3rem;
        font-weight: 900;
        line-height: 1;
        margin: 0.5rem 0;
    }
    .risk-tag {
        display: inline-block;
        font-size: 0.85rem;
        font-weight: 700;
        padding: 0.25rem 0.8rem;
        border-radius: 4px;
        letter-spacing: 1px;
    }
    
    /* Severity Badges */
    .badge-critical {
        background: #450a0a;
        color: #f87171;
        border: 1px solid #ef4444;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 800;
        font-size: 0.75rem;
    }
    .badge-high {
        background: #431407;
        color: #fb923c;
        border: 1px solid #f97316;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 800;
        font-size: 0.75rem;
    }
    .badge-medium {
        background: #422006;
        color: #facc15;
        border: 1px solid #eab308;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 800;
        font-size: 0.75rem;
    }
    .badge-low {
        background: #172554;
        color: #60a5fa;
        border: 1px solid #3b82f6;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 800;
        font-size: 0.75rem;
    }

    /* Code block styling */
    pre, code {
        background-color: #0f172a !important;
        border-color: #1e293b !important;
        color: #38bdf8 !important;
    }

    /* Disclaimer box */
    .disclaimer-banner {
        background: #18181b;
        border-left: 4px solid #06b6d4;
        padding: 0.75rem 1rem;
        font-size: 0.85rem;
        color: #a1a1aa;
        border-radius: 4px;
        margin-top: 1rem;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ============================================================================
# STATE MANAGEMENT
# ============================================================================

if "scan_result" not in st.session_state:
    st.session_state.scan_result = None
if "active_dataset_label" not in st.session_state:
    st.session_state.active_dataset_label = "None"


def load_demo(dataset_type: str):
    """Load sample vulnerable or secure manifests directly."""
    base_dir = Path(__file__).resolve().parent / "examples"
    if dataset_type == "vulnerable":
        target = base_dir / "vulnerable-app"
        res = scan_directory(target)
        st.session_state.scan_result = res
        st.session_state.active_dataset_label = "Vulnerable Demo App"
    elif dataset_type == "secure":
        target = base_dir / "secure-app"
        res = scan_directory(target)
        st.session_state.scan_result = res
        st.session_state.active_dataset_label = "Hardened Reference Architecture"


# ============================================================================
# SIDEBAR: AUDIT CONTROLS & FILE INPUTS
# ============================================================================

with st.sidebar:
    st.markdown("### ⚡ Quick Demo Mode")
    st.caption("Demonstrate before/after security posture in 1-click:")
    
    col_demo1, col_demo2 = st.columns(2)
    with col_demo1:
        if st.button("🔴 Vulnerable App", use_container_width=True, help="Scan intentionally insecure sample app"):
            load_demo("vulnerable")
            st.rerun()
    with col_demo2:
        if st.button("🟢 Secure App", use_container_width=True, help="Scan hardened reference app"):
            load_demo("secure")
            st.rerun()

    st.markdown("---")
    st.markdown("### 📂 Upload Target Artifacts")
    uploaded_files = st.file_uploader(
        "Choose Kubernetes YAML or Dockerfiles",
        accept_multiple_files=True,
        type=["yaml", "yml", "txt", "dockerfile", ""],
        help="Upload multiple Kubernetes manifests, Dockerfiles, or multi-document YAMLs.",
    )

    if uploaded_files:
        if st.button("🔍 Run Security Audit", type="primary", use_container_width=True):
            with st.spinner("Analyzing Kubernetes manifests & Dockerfiles..."):
                all_findings = []
                all_errors = []
                scanned_names = []
                total_resources = 0

                for uploaded in uploaded_files:
                    scanned_names.append(uploaded.name)
                    content = uploaded.getvalue().decode("utf-8", errors="replace")
                    sub_res = scan_content(content, filename=uploaded.name)
                    all_findings.extend(sub_res.findings)
                    all_errors.extend(sub_res.errors)
                    total_resources += sub_res.resources_scanned

                from kube_guard.scoring import calculate_score
                from collections import Counter
                score, risk_lvl = calculate_score(all_findings)
                
                crit = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
                high = sum(1 for f in all_findings if f.severity == Severity.HIGH)
                med = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
                low = sum(1 for f in all_findings if f.severity == Severity.LOW)
                info = sum(1 for f in all_findings if f.severity == Severity.INFO)
                cats = dict(Counter(f.category.value for f in all_findings))

                st.session_state.scan_result = ScanResult(
                    files_scanned=scanned_names,
                    resources_scanned=total_resources,
                    findings=all_findings,
                    score=score,
                    risk_level=risk_lvl,
                    critical_count=crit,
                    high_count=high,
                    medium_count=med,
                    low_count=low,
                    info_count=info,
                    category_counts=cats,
                    errors=all_errors,
                )
                st.session_state.active_dataset_label = f"Uploaded ({len(uploaded_files)} files)"
                st.rerun()

    st.markdown("---")
    st.markdown("### 📝 Paste Raw Snippet")
    with st.expander("Paste YAML or Dockerfile"):
        pasted_type = st.selectbox("Format", ["Kubernetes YAML", "Dockerfile"])
        pasted_content = st.text_area(
            "Paste code here:",
            height=200,
            placeholder="apiVersion: apps/v1\nkind: Deployment...",
        )
        if st.button("Audit Snippet", use_container_width=True):
            if pasted_content.strip():
                fname = "Dockerfile" if pasted_type == "Dockerfile" else "manifest.yaml"
                st.session_state.scan_result = scan_content(pasted_content, filename=fname)
                st.session_state.active_dataset_label = f"Pasted Snippet ({pasted_type})"
                st.rerun()

    st.markdown("---")
    st.caption("🛡️ **KubeGuard v1.0.0** — College Cybersecurity Project")


# Auto-load vulnerable demo app on initial empty launch for instant presentation readiness
if st.session_state.scan_result is None:
    load_demo("vulnerable")


# ============================================================================
# MAIN APPLICATION INTERFACE
# ============================================================================

res: ScanResult = st.session_state.scan_result

# Brand Header Banner
st.markdown(
    """
    <div class="brand-container">
        <h1 class="brand-title">🛡️ Kube<span>Guard</span></h1>
        <div class="brand-subtitle">Container &amp; Kubernetes Security Auditor &bull; Static Posture Assessment</div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Active Target Indicator
col_target, col_reset = st.columns([4, 1])
with col_target:
    st.caption(f"Currently Auditing: **{st.session_state.active_dataset_label}** ({len(res.files_scanned)} files, {res.resources_scanned} resources scanned)")
with col_reset:
    if st.button("Reset View", use_container_width=True):
        load_demo("vulnerable")
        st.rerun()

# Top Score & Severity Executive KPI Row
risk_hex = get_risk_color(res.risk_level)

kpi1, kpi2, kpi3, kpi4, kpi5, kpi6 = st.columns([1.5, 1.5, 1, 1, 1, 1])

with kpi1:
    st.markdown(
        f"""
        <div class="score-card">
            <div style="font-size:0.75rem; font-weight:700; color:#9ca3af; text-transform:uppercase;">Security Score</div>
            <div class="score-number" style="color:{risk_hex};">{res.score} <span style="font-size:1.2rem; color:#6b7280;">/ 100</span></div>
            <div style="font-size:0.75rem; color:#9ca3af;">Deterministic Heuristic</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi2:
    st.markdown(
        f"""
        <div class="score-card">
            <div style="font-size:0.75rem; font-weight:700; color:#9ca3af; text-transform:uppercase;">Evaluated Risk</div>
            <div style="margin: 0.9rem 0;">
                <span class="risk-tag" style="background:{risk_hex}22; color:{risk_hex}; border:1px solid {risk_hex};">
                    {res.risk_level}
                </span>
            </div>
            <div style="font-size:0.75rem; color:#9ca3af;">{res.total_findings} Weaknesses Found</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with kpi3:
    st.metric(label="CRITICAL", value=res.critical_count, delta=f"-{res.critical_count * 20} pts" if res.critical_count else None, delta_color="inverse")

with kpi4:
    st.metric(label="HIGH", value=res.high_count, delta=f"-{res.high_count * 10} pts" if res.high_count else None, delta_color="inverse")

with kpi5:
    st.metric(label="MEDIUM", value=res.medium_count, delta=f"-{res.medium_count * 5} pts" if res.medium_count else None, delta_color="inverse")

with kpi6:
    st.metric(label="LOW", value=res.low_count, delta=f"-{res.low_count * 2} pts" if res.low_count else None, delta_color="inverse")

st.markdown(
    f"""
    <div class="disclaimer-banner">
        <strong>Auditor Note:</strong> {SCORING_DISCLAIMER}
    </div>
    """,
    unsafe_allow_html=True,
)

if res.errors:
    with st.expander(f"⚠️ Parser Warnings ({len(res.errors)})"):
        for err in res.errors:
            st.warning(err)


# ============================================================================
# MAIN TABS NAVIGATION
# ============================================================================

tab_findings, tab_charts, tab_report, tab_compare, tab_methodology = st.tabs([
    "📋 Security Findings",
    "📊 Risk Breakdown & Charts",
    "📄 Audit Report Export",
    "⚖️ Vulnerable vs Secure Demo",
    "📖 Methodology & FAQ",
])


# ============================================================================
# TAB 1: DETAILED FILTERABLE FINDINGS
# ============================================================================

with tab_findings:
    st.markdown("### Security Findings Explorer")
    
    # Filter Row
    fcol1, fcol2, fcol3, fcol4 = st.columns([1.5, 2, 2, 2.5])
    
    with fcol1:
        sev_filter = st.selectbox(
            "Filter Severity",
            ["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        )
    with fcol2:
        all_cats = sorted(list({f.category.value for f in res.findings}))
        cat_filter = st.selectbox("Filter Category", ["All Categories"] + all_cats)
    with fcol3:
        all_files = sorted(list({f.file for f in res.findings}))
        file_filter = st.selectbox("Filter File", ["All Files"] + all_files)
    with fcol4:
        search_query = st.text_input("Search (Rule ID, keyword, resource)", "")

    # Apply filters
    filtered = res.findings
    if sev_filter != "All Severities":
        filtered = [f for f in filtered if f.severity.value == sev_filter]
    if cat_filter != "All Categories":
        filtered = [f for f in filtered if f.category.value == cat_filter]
    if file_filter != "All Files":
        filtered = [f for f in filtered if f.file == file_filter]
    if search_query.strip():
        q = search_query.lower()
        filtered = [
            f for f in filtered
            if q in f.rule_id.lower() or q in f.title.lower() or q in f.resource.lower() or q in f.evidence.lower()
        ]

    st.caption(f"Showing **{len(filtered)}** of **{len(res.findings)}** findings")

    if not filtered:
        st.success("🎉 No security misconfigurations match your active filters.")
    else:
        # Sort priority
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        filtered_sorted = sorted(filtered, key=lambda f: order.get(f.severity, 99))

        for idx, item in enumerate(filtered_sorted, start=1):
            sev_class = f"badge-{item.severity.value.lower()}"
            with st.expander(f"[{item.severity.value}] {item.rule_id} — {item.title}  •  {item.resource}", expanded=(idx <= 3)):
                st.markdown(
                    f"""
                    <div style="display:flex; gap:10px; align-items:center; margin-bottom:12px;">
                        <span class="{sev_class}">{item.severity.value}</span>
                        <span style="font-family:monospace; color:#38bdf8; font-weight:700;">{item.rule_id}</span>
                        <span style="background:#1e293b; color:#cbd5e1; padding:2px 8px; border-radius:4px; font-size:0.8rem;">{item.category.value}</span>
                        <span style="color:#94a3b8; font-size:0.85rem;">📁 {item.file}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                st.markdown(f"**Affected Resource:** `{item.resource}`")
                if item.location:
                    st.markdown(f"**Location in Manifest:** `{item.location}`")

                st.markdown("**Evidence Detected:**")
                st.code(item.evidence, language="yaml")

                col_imp, col_rem = st.columns(2)
                with col_imp:
                    st.markdown("🚨 **Why It Matters & Potential Impact:**")
                    st.info(item.impact)
                with col_rem:
                    st.markdown("🛠️ **Recommended Remediation:**")
                    st.success(item.remediation)

                if item.remediation_yaml:
                    st.markdown("💡 **Remediation Snippet (Correction Blueprint):**")
                    st.code(item.remediation_yaml, language="yaml")

                if item.references:
                    st.caption(f"References: {', '.join(item.references)}")


# ============================================================================
# TAB 2: RISK BREAKDOWN & PLOTLY CHARTS
# ============================================================================

with tab_charts:
    st.markdown("### Risk Analysis & Vulnerability Distribution")
    
    chart_col1, chart_col2 = st.columns(2)
    
    with chart_col1:
        st.markdown("#### Findings by Severity")
        sev_counts = {
            "CRITICAL": res.critical_count,
            "HIGH": res.high_count,
            "MEDIUM": res.medium_count,
            "LOW": res.low_count,
        }
        # Filter out 0 counts for clean donut
        active_sevs = {k: v for k, v in sev_counts.items() if v > 0}
        
        if active_sevs:
            colors_map = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#3b82f6",
            }
            fig_donut = go.Figure(data=[go.Pie(
                labels=list(active_sevs.keys()),
                values=list(active_sevs.values()),
                hole=0.55,
                marker=dict(colors=[colors_map.get(k, "#64748b") for k in active_sevs.keys()]),
                textinfo="label+value",
            )])
            fig_donut.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#f3f4f6"),
                margin=dict(t=20, b=20, l=20, r=20),
                height=320,
            )
            st.plotly_chart(fig_donut, use_container_width=True)
        else:
            st.info("No findings to display in chart.")

    with chart_col2:
        st.markdown("#### Findings by Security Category")
        if res.category_counts:
            cats = list(res.category_counts.keys())
            vals = list(res.category_counts.values())
            fig_bar = px.bar(
                x=vals,
                y=cats,
                orientation="h",
                labels={"x": "Findings Count", "y": "Security Domain"},
                color_discrete_sequence=["#06b6d4"],
            )
            fig_bar.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#f3f4f6"),
                margin=dict(t=20, b=20, l=20, r=20),
                height=320,
                xaxis=dict(showgrid=True, gridcolor="#1f2937"),
                yaxis=dict(showgrid=False),
            )
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("No category data available.")

    st.markdown("---")
    st.markdown("#### Score Deduction Breakdown")
    st.caption("How your security score was computed from detected misconfigurations:")

    ded_data = [
        {"Severity Level": "CRITICAL", "Findings": res.critical_count, "Penalty / Issue": "-20 pts", "Total Deduction": f"-{res.critical_count * 20} pts"},
        {"Severity Level": "HIGH", "Findings": res.high_count, "Penalty / Issue": "-10 pts", "Total Deduction": f"-{res.high_count * 10} pts"},
        {"Severity Level": "MEDIUM", "Findings": res.medium_count, "Penalty / Issue": "-5 pts", "Total Deduction": f"-{res.medium_count * 5} pts"},
        {"Severity Level": "LOW", "Findings": res.low_count, "Penalty / Issue": "-2 pts", "Total Deduction": f"-{res.low_count * 2} pts"},
    ]
    st.table(ded_data)


# ============================================================================
# TAB 3: AUDIT REPORT EXPORT
# ============================================================================

with tab_report:
    st.markdown("### Executive Security Audit Report")
    st.caption("Generate and download a self-contained HTML audit report for compliance reviews or submission.")

    html_report = generate_html_report(res)
    
    col_dl, col_blank = st.columns([2, 5])
    with col_dl:
        st.download_button(
            label="📥 Download HTML Report",
            data=html_report,
            file_name=f"KubeGuard_Audit_Report_{res.risk_level.replace(' ', '_')}.html",
            mime="text/html",
            type="primary",
            use_container_width=True,
        )

    st.markdown("#### Report Preview")
    # Embedded HTML render preview
    st.components.v1.html(html_report, height=650, scrolling=True)


# ============================================================================
# TAB 4: VULNERABLE VS SECURE BENCHMARK COMPARISON
# ============================================================================

with tab_compare:
    st.markdown("### Side-by-Side Security Posture Comparison")
    st.caption("Demonstrate the power of Kubernetes hardening by comparing the Vulnerable App against the Secure App:")

    col_btn_vuln, col_btn_sec = st.columns(2)
    with col_btn_vuln:
        if st.button("Load Vulnerable Baseline", use_container_width=True):
            load_demo("vulnerable")
            st.rerun()
    with col_btn_sec:
        if st.button("Load Hardened Configuration", use_container_width=True):
            load_demo("secure")
            st.rerun()

    # Pre-calculate both for the presentation table
    base_examples = Path(__file__).resolve().parent / "examples"
    res_vuln = scan_directory(base_examples / "vulnerable-app")
    res_sec = scan_directory(base_examples / "secure-app")

    comp_col1, comp_col2 = st.columns(2)
    
    with comp_col1:
        st.markdown(
            f"""
            <div style="background:#1c1017; border:2px solid #ef4444; border-radius:10px; padding:20px; text-align:center;">
                <h3 style="color:#ef4444; margin:0;">🔴 Vulnerable Architecture</h3>
                <div style="font-size:2.5rem; font-weight:900; color:#ef4444; margin:10px 0;">{res_vuln.score} / 100</div>
                <div style="color:#f87171; font-weight:700;">{res_vuln.risk_level}</div>
                <hr style="border-color:#3f1418; margin:15px 0;">
                <div style="text-align:left; font-size:0.9rem;">
                    <div>⚠️ <strong>Critical:</strong> {res_vuln.critical_count}</div>
                    <div>⚠️ <strong>High:</strong> {res_vuln.high_count}</div>
                    <div>⚠️ <strong>Medium:</strong> {res_vuln.medium_count}</div>
                    <div>⚠️ <strong>Low:</strong> {res_vuln.low_count}</div>
                    <div style="margin-top:8px;">❌ Privileged container allowed</div>
                    <div>❌ Running as Root UID 0</div>
                    <div>❌ Host filesystem mounted (/)</div>
                    <div>❌ Wildcard RBAC permissions (*)</div>
                    <div>❌ Hardcoded plaintext credentials</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with comp_col2:
        st.markdown(
            f"""
            <div style="background:#091e1d; border:2px solid #22c55e; border-radius:10px; padding:20px; text-align:center;">
                <h3 style="color:#22c55e; margin:0;">🟢 Hardened Architecture</h3>
                <div style="font-size:2.5rem; font-weight:900; color:#22c55e; margin:10px 0;">{res_sec.score} / 100</div>
                <div style="color:#86efac; font-weight:700;">{res_sec.risk_level}</div>
                <hr style="border-color:#133729; margin:15px 0;">
                <div style="text-align:left; font-size:0.9rem;">
                    <div>🛡️ <strong>Critical:</strong> {res_sec.critical_count}</div>
                    <div>🛡️ <strong>High:</strong> {res_sec.high_count}</div>
                    <div>🛡️ <strong>Medium:</strong> {res_sec.medium_count}</div>
                    <div>🛡️ <strong>Low:</strong> {res_sec.low_count}</div>
                    <div style="margin-top:8px;">✅ Non-root user (UID 10001) enforced</div>
                    <div>✅ Read-only root filesystem enabled</div>
                    <div>✅ All Linux capabilities dropped (drop: ALL)</div>
                    <div>✅ Granular least-privilege Role &amp; RoleBinding</div>
                    <div>✅ Secrets decoupled via secretKeyRef</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


# ============================================================================
# TAB 5: METHODOLOGY & ARCHITECTURE
# ============================================================================

with tab_methodology:
    st.markdown("### 📚 Security Methodology & Architecture")
    
    st.markdown(
        """
        #### What is Kubernetes & Container Security?
        Kubernetes orchestrates containerized workloads across compute clusters. However, default configurations prioritize developer convenience over security:
        - By default, containers can run with root privileges.
        - Processes can communicate unrestricted across flat networks.
        - Containers may inherit access to node devices or host filesystems.
        - Overly broad RBAC roles create paths for cluster takeover.

        #### What KubeGuard Does (Static Configuration Analysis)
        **KubeGuard** acts as an automated static policy auditor for infrastructure-as-code (IaC). It inspects Kubernetes YAML manifests and Dockerfiles before deployment, mapping misconfigurations against the **Kubernetes Pod Security Standards (Restricted Profile)**, **CIS Kubernetes Benchmarks**, and **OWASP Docker Security Cheatsheets**.

        #### The Scoring System
        - **Baseline:** 100 points
        - **Deductions:**
            - **CRITICAL (-20 pts):** Direct host compromise or unrestricted root privilege escalation (e.g., privileged container, plaintext credentials).
            - **HIGH (-10 pts):** Severe isolation bypasses (e.g., hostPID, hostNetwork, hostPath mount, wildcard RBAC).
            - **MEDIUM (-5 pts):** Missing security controls or hygiene failures (e.g., missing resource limits, :latest tags, plain HTTP Ingress).
            - **LOW (-2 pts):** Defense-in-depth suggestions (e.g., missing AppArmor profile, missing resource requests).
        - **Risk Brackets:**
            - `90 - 100`: **LOW RISK**
            - `70 - 89`: **MODERATE RISK**
            - `40 - 69`: **HIGH RISK**
            - `0 - 39`: **CRITICAL RISK**

        #### What KubeGuard Does NOT Do (Honest Tool Scope)
        1. **Not a Live Penetration Testing Tool:** KubeGuard does not attack or exploit running clusters.
        2. **Not a CVE Vulnerability Scanner:** It checks configuration syntax, not binary package CVEs inside image layers (use **Trivy** or **Grype** for CVE scanning).
        3. **Not a Runtime Threat Monitor:** It does not inspect kernel syscalls during execution (use **Falco** for runtime eBPF threat detection).
        4. **Not a Replacement for CIS Scans:** Use **kube-bench** to audit master/worker node host operating system settings.
        """
    )
