import sys
try:
    import pkg_resources  # noqa: F401
except ImportError:
    try:
        import setuptools as _st
        sys.modules['pkg_resources'] = _st
    except ImportError:
        from types import ModuleType as _M
        sys.modules['pkg_resources'] = _M('pkg_resources')

# ---------------------------------------------------------------------------
# app.py
# ------
# AegisAgent — Streamlit SOC Dashboard.
#
# Runs the full multi-agent incident response pipeline through an interactive
# dark-mode cybersecurity dashboard.
#
# Usage:
#     streamlit run app.py
# ---------------------------------------------------------------------------

import os
import time
import streamlit as st
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Environment — loaded before any agent/task module is imported
# ---------------------------------------------------------------------------
load_dotenv()

# ---------------------------------------------------------------------------
# Page configuration — MUST be the first Streamlit call in the script
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="AegisAgent · Cyber Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS — dark SOC dashboard aesthetic
# ---------------------------------------------------------------------------
DARK_CSS = """
<style>
/* ── Global ──────────────────────────────────────────────────────────── */
html, body, [class*="css"] {
    font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
    background-color: #0d1117;
    color: #c9d1d9;
}
.stApp { background-color: #0d1117; }

/* ── Sidebar ─────────────────────────────────────────────────────────── */
section[data-testid="stSidebar"] {
    background-color: #161b22;
    border-right: 1px solid #30363d;
}
section[data-testid="stSidebar"] * { color: #8b949e !important; }
section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3 { color: #58a6ff !important; }

/* ── Headings ────────────────────────────────────────────────────────── */
h1 { color: #58a6ff !important; letter-spacing: 1px; }
h2 { color: #79c0ff !important; }
h3 { color: #a5d6ff !important; }

/* ── Buttons ─────────────────────────────────────────────────────────── */
.stButton > button {
    background: linear-gradient(135deg, #1f6feb 0%, #388bfd 100%);
    color: #ffffff;
    border: none;
    border-radius: 6px;
    padding: 0.55rem 1.4rem;
    font-weight: 700;
    font-size: 0.9rem;
    letter-spacing: 0.5px;
    transition: opacity 0.2s;
}
.stButton > button:hover   { opacity: 0.85; }
.stButton > button:disabled { opacity: 0.4; cursor: not-allowed; }

/* ── Text area ───────────────────────────────────────────────────────── */
textarea {
    background-color: #0d1117 !important;
    color: #c9d1d9 !important;
    border: 1px solid #30363d !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.78rem !important;
}

/* ── Expanders ───────────────────────────────────────────────────────── */
details {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    margin-bottom: 0.75rem;
}
details summary { color: #58a6ff !important; font-weight: 600; padding: 0.5rem; }

/* ── Code blocks ─────────────────────────────────────────────────────── */
code, pre {
    background-color: #161b22 !important;
    color: #d2a8ff !important;
    border: 1px solid #30363d;
    border-radius: 6px;
}

/* ── Severity badge helpers ──────────────────────────────────────────── */
.badge-low      { background:#238636; color:#fff; padding:2px 8px; border-radius:12px; font-size:0.8rem; font-weight:700; }
.badge-medium   { background:#9e6a03; color:#fff; padding:2px 8px; border-radius:12px; font-size:0.8rem; font-weight:700; }
.badge-high     { background:#da3633; color:#fff; padding:2px 8px; border-radius:12px; font-size:0.8rem; font-weight:700; }
.badge-critical { background:#6e40c9; color:#fff; padding:2px 8px; border-radius:12px; font-size:0.8rem; font-weight:700; }

/* ── Metrics ─────────────────────────────────────────────────────────── */
[data-testid="metric-container"] {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 0.75rem 1rem;
}

/* ── Progress bar ────────────────────────────────────────────────────── */
.stProgress > div > div { background-color: #1f6feb; }

/* ── File uploader ───────────────────────────────────────────────────── */
[data-testid="stFileUploader"] {
    background-color: #161b22;
    border: 1px dashed #30363d;
    border-radius: 8px;
}

/* ── Divider ─────────────────────────────────────────────────────────── */
hr { border-color: #30363d; }
</style>
"""

st.markdown(DARK_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Lazy imports — deferred so a missing API key surfaces only on analysis run
# ---------------------------------------------------------------------------
def _import_pipeline():
    """Import log-parser utilities only when the user triggers analysis."""
    from utils.log_parser import parse_logs, filter_suspicious_logs, format_for_llm
    return parse_logs, filter_suspicious_logs, format_for_llm


# ---------------------------------------------------------------------------
# Session-state initialisation
# ---------------------------------------------------------------------------
_STATE_DEFAULTS: dict = {
    "analysis_done":    False,
    "step_watchdog":    None,
    "step_intel":       None,
    "step_responder":   None,
    "final_report":     None,
    "parsed_count":     0,
    "suspicious_count": 0,
    "severity":         "—",
    "error":            None,
    "running":          False,
}

for _k, _v in _STATE_DEFAULTS.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SAMPLE_LOGS = (
    '192.168.1.105 - - [28/Oct/2026:03:14:22 +0000] "POST /admin/login HTTP/1.1" 401 512 "-" "python-requests/2.28"\n'
    '192.168.1.105 - - [28/Oct/2026:03:14:25 +0000] "POST /admin/login HTTP/1.1" 401 512 "-" "python-requests/2.28"\n'
    '192.168.1.105 - - [28/Oct/2026:03:14:28 +0000] "POST /admin/login HTTP/1.1" 401 512 "-" "python-requests/2.28"\n'
    '192.168.1.105 - - [28/Oct/2026:03:14:31 +0000] "POST /admin/login HTTP/1.1" 401 512 "-" "python-requests/2.28"\n'
    '192.168.1.105 - - [28/Oct/2026:03:14:34 +0000] "POST /admin/login HTTP/1.1" 401 512 "-" "python-requests/2.28"\n'
    '10.0.0.47 - - [28/Oct/2026:03:15:01 +0000] "GET /index.php?id=1+OR+1%3D1-- HTTP/1.1" 500 1024 "-" "sqlmap/1.7"\n'
    '10.0.0.47 - - [28/Oct/2026:03:15:03 +0000] "GET /index.php?id=1+UNION+SELECT+1,2,3-- HTTP/1.1" 500 1024 "-" "sqlmap/1.7"\n'
    '203.0.113.77 - - [28/Oct/2026:03:16:45 +0000] "GET /../../../etc/passwd HTTP/1.1" 403 256 "-" "curl/7.74.0"\n'
    '172.16.0.33 - - [28/Oct/2026:03:17:10 +0000] "GET /search?q=%3Cscript%3Ealert%28xss%29%3C%2Fscript%3E HTTP/1.1" 400 128 "-" "Mozilla/5.0"\n'
    '198.51.100.9 - - [28/Oct/2026:03:18:00 +0000] "DELETE /api/v1/users/42 HTTP/1.1" 403 64 "-" "Nikto/2.1.6"\n'
    '10.0.0.1 - - [28/Oct/2026:03:20:00 +0000] "GET /index.html HTTP/1.1" 200 4096 "-" "Mozilla/5.0"\n'
)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def _severity_badge(level: str) -> str:
    mapping = {
        "low":      '<span class="badge-low">LOW</span>',
        "medium":   '<span class="badge-medium">MEDIUM</span>',
        "high":     '<span class="badge-high">HIGH</span>',
        "critical": '<span class="badge-critical">CRITICAL</span>',
    }
    return mapping.get(level.lower(), f"<b>{level.upper()}</b>")


def _detect_severity(report_text: str) -> str:
    """Heuristically extract the highest severity level mentioned in the report."""
    text = report_text.lower()
    for level in ("critical", "high", "medium", "low"):
        if level in text:
            return level.capitalize()
    return "Unknown"


# ---------------------------------------------------------------------------
# Main analysis runner
# ---------------------------------------------------------------------------
def run_analysis(log_text: str) -> None:
    """Execute the full pipeline and persist all results in session state."""
    st.session_state.running = True
    st.session_state.error   = None

    # -- Import pipeline dependencies ----------------------------------------
    try:
        parse_logs, filter_suspicious_logs, format_for_llm = _import_pipeline()
    except EnvironmentError as exc:
        st.session_state.error   = str(exc)
        st.session_state.running = False
        return
    except ImportError as exc:
        st.session_state.error = (
            f"Dependency import failed: {exc}\n"
            "Run:  pip install -r requirements.txt"
        )
        st.session_state.running = False
        return

    # -- Step 1: Parse & filter logs -----------------------------------------
    progress = st.progress(0, text="⏳ Parsing logs…")
    parsed     = parse_logs(log_text)
    suspicious = filter_suspicious_logs(parsed)
    formatted  = format_for_llm(suspicious)

    st.session_state.parsed_count     = len(parsed)
    st.session_state.suspicious_count = len(suspicious)

    if not suspicious:
        st.session_state.error = (
            "No suspicious log entries detected after filtering. "
            "Provide logs with authentication failures, error responses, "
            "or injection patterns."
        )
        st.session_state.running = False
        progress.empty()
        return

    # -- Step 2: Run each agent with live status feedback --------------------
    from agents import run_watchdog, run_intel_analyst, run_responder

    watchdog_output = intel_output = responder_output = ""

    try:
        progress.progress(15, text="🔍 [1/3] Watchdog — extracting IoCs…")
        with st.status("🔍 **Watchdog Agent** — Extracting IoCs…", expanded=True) as s1:
            st.write("Scanning log entries for suspicious patterns…")
            st.caption("⏳ Free Tier: auto-retries on rate limit — please wait")
            watchdog_output = run_watchdog(formatted)
            s1.update(label="✅ Watchdog complete", state="complete", expanded=False)

        progress.progress(40, text="⏳ Cooldown between agents (Free Tier)…")
        time.sleep(15)  # stay within 5 req/min free-tier limit

        progress.progress(50, text="🧠 [2/3] IntelAnalyst — MITRE mapping…")
        with st.status("🧠 **IntelAnalyst Agent** — Mapping to MITRE ATT&CK…", expanded=True) as s2:
            st.write("Classifying threat vectors and assigning severity…")
            st.caption("⏳ Free Tier: auto-retries on rate limit — please wait")
            intel_output = run_intel_analyst(watchdog_output)
            s2.update(label="✅ IntelAnalyst complete", state="complete", expanded=False)

        progress.progress(70, text="⏳ Cooldown between agents (Free Tier)…")
        time.sleep(15)  # stay within 5 req/min free-tier limit

        progress.progress(80, text="🚨 [3/3] Responder — generating report…")
        with st.status("🚨 **Responder Agent** — Drafting mitigation & report…", expanded=True) as s3:
            st.write("Writing firewall script and forensic incident report…")
            st.caption("⏳ Free Tier: auto-retries on rate limit — please wait")
            responder_output = run_responder(watchdog_output, intel_output)
            s3.update(label="✅ Responder complete", state="complete", expanded=False)

    except Exception as exc:
        st.session_state.error = (
            f"Agent execution failed: {exc}\n\n"
            "Verify your GOOGLE_API_KEY is valid and has Gemini API access."
        )
        st.session_state.running = False
        progress.empty()
        return

    progress.progress(95, text="📝 Saving results…")
    time.sleep(0.2)

    # -- Step 3: Persist results ---------------------------------------------
    st.session_state.step_watchdog  = watchdog_output
    st.session_state.step_intel     = intel_output
    st.session_state.step_responder = responder_output
    st.session_state.final_report   = responder_output
    st.session_state.severity       = _detect_severity(responder_output)
    st.session_state.analysis_done  = True
    st.session_state.running        = False

    progress.progress(100, text="✅ Analysis complete")
    time.sleep(0.4)
    progress.empty()


# ===========================================================================
# SIDEBAR
# ===========================================================================
with st.sidebar:
    st.markdown("## 🛡️ AegisAgent")
    st.markdown("**Autonomous Cyber Defense System**")
    st.markdown("---")
    st.markdown(
        "**Pipeline**\n\n"
        "1. 🔍 **Watchdog** — IoC Extraction\n"
        "2. 🧠 **IntelAnalyst** — MITRE Mapping\n"
        "3. 🚨 **Responder** — Mitigation & Report"
    )
    st.markdown("---")
    st.markdown("**LLM:** `gemini-1.5-flash`")
    st.markdown("**Framework:** LangChain · Google Gemini")
    st.markdown("---")

    if st.session_state.analysis_done:
        st.markdown("### 📊 Session Stats")
        st.metric("Total Log Lines",    st.session_state.parsed_count)
        st.metric("Suspicious Entries", st.session_state.suspicious_count)
        sev_sidebar = st.session_state.severity
        st.markdown(
            f"**Severity:** {_severity_badge(sev_sidebar)}",
            unsafe_allow_html=True,
        )

    st.markdown("---")
    if st.button("🔄 Reset Session", use_container_width=True):
        for _k, _v in _STATE_DEFAULTS.items():
            st.session_state[_k] = _v
        st.rerun()


# ===========================================================================
# MAIN LAYOUT
# ===========================================================================
st.markdown("# 🛡️ AegisAgent")
st.markdown("##### Autonomous Cyber Defense System · Powered by LangChain & Google Gemini")
st.markdown("---")

# ---------------------------------------------------------------------------
# Input section
# ---------------------------------------------------------------------------
col_left, col_right = st.columns([3, 1], gap="large")

with col_left:
    st.markdown("### 📥 Log Input")
    tab_paste, tab_upload = st.tabs(["✏️ Paste Logs", "📂 Upload File"])

    with tab_paste:
        log_input_pasted = st.text_area(
            label="Paste server / network logs",
            height=280,
            placeholder='192.168.1.1 - - [28/Oct/2026:03:14:22 +0000] "POST /login HTTP/1.1" 401 512 ...',
            label_visibility="collapsed",
            key="log_textarea",
        )
        if st.button("📋 Load Sample Logs", use_container_width=False):
            st.session_state.log_textarea = SAMPLE_LOGS
            st.rerun()

    with tab_upload:
        uploaded_file = st.file_uploader(
            "Upload a .log or .txt file",
            type=["log", "txt"],
            label_visibility="collapsed",
        )
        if uploaded_file is not None:
            log_input_uploaded = uploaded_file.read().decode("utf-8", errors="replace")
            st.success(
                f"✅ Loaded **{uploaded_file.name}** "
                f"({len(log_input_uploaded.splitlines())} lines)"
            )
            with st.expander("Preview", expanded=False):
                st.code(
                    log_input_uploaded[:2000]
                    + ("…" if len(log_input_uploaded) > 2000 else "")
                )
        else:
            log_input_uploaded = ""

# Resolve active log: upload takes priority over paste
active_log: str = log_input_uploaded if log_input_uploaded.strip() else log_input_pasted

with col_right:
    st.markdown("### ⚡ Controls")
    _api_key_env = os.getenv("GOOGLE_API_KEY", "")
    api_ok = bool(_api_key_env and _api_key_env != "your_google_gemini_api_key_here")

    if not api_ok:
        st.warning("⚠️ GOOGLE_API_KEY not set.\nEdit `.env` to continue.", icon="🔑")

    analyze_clicked = st.button(
        "🚀 Run Analysis",
        disabled=(st.session_state.running or not api_ok),
        use_container_width=True,
        type="primary",
    )
    st.markdown("&nbsp;")
    st.info(
        "**How it works**\n\n"
        "1. Regex engine parses & filters logs.\n"
        "2. Watchdog agent extracts IoCs.\n"
        "3. IntelAnalyst maps to MITRE ATT&CK.\n"
        "4. Responder generates report & script.",
        icon="ℹ️",
    )

# ---------------------------------------------------------------------------
# Trigger analysis
# ---------------------------------------------------------------------------
if analyze_clicked and active_log.strip():
    run_analysis(active_log)
    st.rerun()
elif analyze_clicked and not active_log.strip():
    st.warning("⚠️ Please paste logs or upload a file before running analysis.")

# ---------------------------------------------------------------------------
# Error display
# ---------------------------------------------------------------------------
if st.session_state.error:
    st.error(f"❌ **Error:** {st.session_state.error}", icon="🚨")


# ===========================================================================
# RESULTS SECTION
# ===========================================================================
if st.session_state.analysis_done:
    st.markdown("---")
    st.markdown("## 🔬 Analysis Results")

    # -- Severity banner -----------------------------------------------------
    sev = st.session_state.severity
    sev_colors = {
        "Low":      "#238636",
        "Medium":   "#9e6a03",
        "High":     "#da3633",
        "Critical": "#6e40c9",
        "Unknown":  "#30363d",
    }
    banner_color = sev_colors.get(sev, "#30363d")
    st.markdown(
        f'<div style="background:{banner_color};border-radius:8px;padding:0.75rem 1.25rem;'
        f'margin-bottom:1rem;font-size:1.1rem;font-weight:700;letter-spacing:1px;">'
        f"🚨 THREAT SEVERITY: {sev.upper()}"
        f"</div>",
        unsafe_allow_html=True,
    )

    # -- Metrics row ---------------------------------------------------------
    m1, m2, m3 = st.columns(3)
    m1.metric("📄 Total Log Lines",    st.session_state.parsed_count)
    m2.metric("🚩 Suspicious Entries", st.session_state.suspicious_count)
    m3.metric("⚠️  Severity Level",    sev)

    st.markdown("---")

    # -- Agent output expanders ----------------------------------------------
    st.markdown("### 🤖 Agent Outputs")

    with st.expander("🔍 Watchdog Agent — IoC Inventory", expanded=True):
        trace = st.session_state.step_watchdog or ""
        if trace.strip():
            st.markdown(trace)
        else:
            st.info("No output captured for this stage.")

    with st.expander("🧠 IntelAnalyst Agent — MITRE ATT&CK Brief", expanded=False):
        trace = st.session_state.step_intel or ""
        if trace.strip():
            st.markdown(trace)
        else:
            st.info("No output captured for this stage.")

    with st.expander("🚨 Responder Agent — Mitigation Script & Report", expanded=False):
        trace = st.session_state.step_responder or ""
        if trace.strip():
            st.markdown(trace)
        else:
            st.info("No output captured for this stage.")

    st.markdown("---")

    # -- Final report download -----------------------------------------------
    st.markdown("### 📋 Full Forensic Report")
    report_text = st.session_state.final_report or ""
    st.markdown(report_text, unsafe_allow_html=False)

    st.download_button(
        label="⬇️ Download Full Report (.md)",
        data=report_text.encode("utf-8"),
        file_name="aegisagent_incident_report.md",
        mime="text/markdown",
    )

elif st.session_state.running:
    st.info("⏳ Analysis in progress… Please wait.", icon="🔄")

else:
    # Idle placeholder
    st.markdown("---")
    st.markdown(
        '<div style="background:#161b22;border:1px solid #30363d;border-radius:10px;'
        'padding:2rem;text-align:center;color:#8b949e;">'
        '<h3 style="color:#58a6ff;">Awaiting Log Input</h3>'
        "<p>Paste server logs or upload a file, then click <b>🚀 Run Analysis</b>.</p>"
        "<p style=\"font-size:0.85rem;\">Supports Apache / Nginx Combined Log Format</p>"
        "</div>",
        unsafe_allow_html=True,
    )

# ===========================================================================
# FOOTER
# ===========================================================================
st.markdown("---")
st.markdown(
    '<p style="text-align:center;font-size:0.75rem;color:#484f58;">'
    "AegisAgent · IBM SkillsBuild Capstone · Built with LangChain, Gemini & Streamlit"
    "</p>",
    unsafe_allow_html=True,
)
