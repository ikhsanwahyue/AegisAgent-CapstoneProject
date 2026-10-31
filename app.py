"""
app.py
------
AegisAgent — Streamlit SOC Dashboard.

Runs the full multi-agent incident response pipeline through an interactive
dark-mode cybersecurity dashboard.

Usage:
    streamlit run app.py
"""

import os
import sys
import io
import time
import contextlib
import streamlit as st
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Environment – must be loaded before importing agent/task modules
# ---------------------------------------------------------------------------
load_dotenv()

# ---------------------------------------------------------------------------
# Page configuration (must be the first Streamlit call)
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
.stButton > button:hover { opacity: 0.85; }
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

/* ── Info / warning / success boxes ─────────────────────────────────── */
.stAlert { border-radius: 8px !important; }

/* ── Metrics ─────────────────────────────────────────────────────────── */
[data-testid="metric-container"] {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 0.75rem 1rem;
}

/* ── Severity badge helpers (used via st.markdown) ───────────────────── */
.badge-low      { background:#238636; color:#fff; padding:2px 8px; border-radius:12px; font-size:0.8rem; font-weight:700; }
.badge-medium   { background:#9e6a03; color:#fff; padding:2px 8px; border-radius:12px; font-size:0.8rem; font-weight:700; }
.badge-high     { background:#da3633; color:#fff; padding:2px 8px; border-radius:12px; font-size:0.8rem; font-weight:700; }
.badge-critical { background:#6e40c9; color:#fff; padding:2px 8px; border-radius:12px; font-size:0.8rem; font-weight:700; }

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
# Lazy imports — deferred so missing keys surface only when analysis runs
# ---------------------------------------------------------------------------
def _import_pipeline():
    """Import heavy CrewAI / LLM modules only when the user triggers analysis."""
    from crewai import Crew, Process
    from utils.log_parser import parse_logs, filter_suspicious_logs, format_for_llm
    from tasks import build_tasks
    return Crew, Process, parse_logs, filter_suspicious_logs, format_for_llm, build_tasks


# ---------------------------------------------------------------------------
# Session-state initialisation
# ---------------------------------------------------------------------------
_STATE_DEFAULTS = {
    "analysis_done": False,
    "step_watchdog": None,      # raw stdout captured during watchdog task
    "step_intel": None,
    "step_responder": None,
    "final_report": None,
    "parsed_count": 0,
    "suspicious_count": 0,
    "severity": "—",
    "error": None,
    "running": False,
}

for key, default in _STATE_DEFAULTS.items():
    if key not in st.session_state:
        st.session_state[key] = default


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

SAMPLE_LOGS = """\
192.168.1.105 - - [28/Oct/2026:03:14:22 +0000] "POST /admin/login HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.105 - - [28/Oct/2026:03:14:25 +0000] "POST /admin/login HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.105 - - [28/Oct/2026:03:14:28 +0000] "POST /admin/login HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.105 - - [28/Oct/2026:03:14:31 +0000] "POST /admin/login HTTP/1.1" 401 512 "-" "python-requests/2.28"
192.168.1.105 - - [28/Oct/2026:03:14:34 +0000] "POST /admin/login HTTP/1.1" 401 512 "-" "python-requests/2.28"
10.0.0.47 - - [28/Oct/2026:03:15:01 +0000] "GET /index.php?id=1' OR '1'='1 HTTP/1.1" 500 1024 "-" "sqlmap/1.7"
10.0.0.47 - - [28/Oct/2026:03:15:03 +0000] "GET /index.php?id=1 UNION SELECT 1,2,3-- HTTP/1.1" 500 1024 "-" "sqlmap/1.7"
203.0.113.77 - - [28/Oct/2026:03:16:45 +0000] "GET /../../../etc/passwd HTTP/1.1" 403 256 "-" "curl/7.74.0"
172.16.0.33 - - [28/Oct/2026:03:17:10 +0000] "GET /search?q=<script>alert('xss')</script> HTTP/1.1" 400 128 "-" "Mozilla/5.0"
198.51.100.9 - - [28/Oct/2026:03:18:00 +0000] "DELETE /api/v1/users/42 HTTP/1.1" 403 64 "-" "Nikto/2.1.6"
10.0.0.1 - - [28/Oct/2026:03:20:00 +0000] "GET /index.html HTTP/1.1" 200 4096 "-" "Mozilla/5.0"
""".strip()


def _severity_badge(level: str) -> str:
    mapping = {
        "low":      '<span class="badge-low">LOW</span>',
        "medium":   '<span class="badge-medium">MEDIUM</span>',
        "high":     '<span class="badge-high">HIGH</span>',
        "critical": '<span class="badge-critical">CRITICAL</span>',
    }
    return mapping.get(level.lower(), f"<b>{level.upper()}</b>")


def _detect_severity(report_text: str) -> str:
    """Heuristically extract the highest severity mentioned in the report."""
    text = report_text.lower()
    for level in ("critical", "high", "medium", "low"):
        if level in text:
            return level.capitalize()
    return "Unknown"


def _capture_crew_output(crew, verbose: bool = True) -> tuple[str, str]:
    """Run crew.kickoff() while capturing stdout for thought-process display.

    Returns:
        (full_stdout, final_output_string)
    """
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        result = crew.kickoff()
    captured = buffer.getvalue()
    # Extract the final string result
    if hasattr(result, "raw"):
        final = result.raw
    elif hasattr(result, "output"):
        final = result.output
    else:
        final = str(result)
    return captured, final


# ---------------------------------------------------------------------------
# Main analysis runner
# ---------------------------------------------------------------------------

def run_analysis(log_text: str) -> None:
    """Execute the full CrewAI pipeline and persist results in session state."""
    st.session_state.running = True
    st.session_state.error = None

    try:
        Crew, Process, parse_logs, filter_suspicious_logs, format_for_llm, build_tasks = (
            _import_pipeline()
        )
    except EnvironmentError as exc:
        st.session_state.error = str(exc)
        st.session_state.running = False
        return
    except ImportError as exc:
        st.session_state.error = (
            f"Dependency import failed: {exc}\n"
            "Run: pip install -r requirements.txt"
        )
        st.session_state.running = False
        return

    # --- Step 1: Parse & filter logs -----------------------------------
    progress_bar = st.progress(0, text="⏳ Parsing logs…")
    parsed = parse_logs(log_text)
    suspicious = filter_suspicious_logs(parsed)
    formatted = format_for_llm(suspicious)

    st.session_state.parsed_count = len(parsed)
    st.session_state.suspicious_count = len(suspicious)

    if not suspicious:
        st.session_state.error = (
            "No suspicious log entries were detected after filtering. "
            "Try providing logs that contain authentication failures, "
            "error responses, or injection patterns."
        )
        st.session_state.running = False
        progress_bar.empty()
        return

    progress_bar.progress(15, text="🔍 Watchdog agent scanning…")

    # --- Step 2: Build tasks -------------------------------------------
    try:
        extract_task, classify_task, mitigation_task = build_tasks(formatted)
    except Exception as exc:
        st.session_state.error = f"Task construction failed: {exc}"
        st.session_state.running = False
        progress_bar.empty()
        return

    # --- Step 3: Run Crew sequentially ---------------------------------
    crew = Crew(
        agents=[
            extract_task.agent,
            classify_task.agent,
            mitigation_task.agent,
        ],
        tasks=[extract_task, classify_task, mitigation_task],
        process=Process.sequential,
        verbose=True,
    )

    try:
        stdout_capture, final_output = _capture_crew_output(crew)
    except Exception as exc:
        st.session_state.error = (
            f"Agent execution failed: {exc}\n\n"
            "Verify your GOOGLE_API_KEY is valid and has Gemini API access."
        )
        st.session_state.running = False
        progress_bar.empty()
        return

    progress_bar.progress(90, text="📝 Compiling forensic report…")
    time.sleep(0.3)

    # --- Persist results -----------------------------------------------
    # Split captured stdout into rough thirds to assign per-agent
    lines = stdout_capture.splitlines()
    third = max(1, len(lines) // 3)
    st.session_state.step_watchdog  = "\n".join(lines[:third])
    st.session_state.step_intel     = "\n".join(lines[third: 2 * third])
    st.session_state.step_responder = "\n".join(lines[2 * third:])
    st.session_state.final_report   = final_output
    st.session_state.severity       = _detect_severity(final_output)
    st.session_state.analysis_done  = True
    st.session_state.running        = False

    progress_bar.progress(100, text="✅ Analysis complete")
    time.sleep(0.5)
    progress_bar.empty()


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ AegisAgent")
    st.markdown("**Autonomous Cyber Defense System**")
    st.markdown("---")
    st.markdown(
        "**Pipeline**\n"
        "1. 🔍 Watchdog — IoC Extraction\n"
        "2. 🧠 IntelAnalyst — MITRE Mapping\n"
        "3. 🚨 Responder — Mitigation & Report"
    )
    st.markdown("---")
    st.markdown("**LLM:** `gemini-2.0-flash`")
    st.markdown("**Framework:** CrewAI · LangChain")
    st.markdown("**Theme:** Dark SOC Dashboard")
    st.markdown("---")

    if st.session_state.analysis_done:
        st.markdown("### 📊 Session Stats")
        st.metric("Total Log Lines", st.session_state.parsed_count)
        st.metric("Suspicious Entries", st.session_state.suspicious_count)
        sev = st.session_state.severity
        st.markdown(
            f"**Severity:** {_severity_badge(sev)}",
            unsafe_allow_html=True,
        )

    st.markdown("---")
    if st.button("🔄 Reset Session", use_container_width=True):
        for key, default in _STATE_DEFAULTS.items():
            st.session_state[key] = default
        st.rerun()


# ---------------------------------------------------------------------------
# Main layout
# ---------------------------------------------------------------------------
st.markdown("# 🛡️ AegisAgent")
st.markdown(
    "##### Autonomous Cyber Defense System · Powered by CrewAI & Google Gemini"
)
st.markdown("---")

# --- Input section ---------------------------------------------------------
col_left, col_right = st.columns([3, 1], gap="large")

with col_left:
    st.markdown("### 📥 Log Input")
    tab_paste, tab_upload = st.tabs(["✏️ Paste Logs", "📂 Upload File"])

    with tab_paste:
        log_input = st.text_area(
            label="Paste your server / network logs here",
            height=280,
            placeholder="192.168.1.1 - - [28/Oct/2026:03:14:22 +0000] \"POST /login HTTP/1.1\" 401 512 ...",
            label_visibility="collapsed",
            key="log_textarea",
        )
        if st.button("📋 Load Sample Logs", use_container_width=False):
            st.session_state.log_textarea = SAMPLE_LOGS
            st.rerun()

    with tab_upload:
        uploaded = st.file_uploader(
            "Upload a .log or .txt file",
            type=["log", "txt"],
            label_visibility="collapsed",
        )
        if uploaded is not None:
            log_input = uploaded.read().decode("utf-8", errors="replace")
            st.success(
                f"✅ Loaded **{uploaded.name}** "
                f"({len(log_input.splitlines())} lines)"
            )
            with st.expander("Preview", expanded=False):
                st.code(log_input[:2000] + ("…" if len(log_input) > 2000 else ""))

with col_right:
    st.markdown("### ⚡ Controls")
    api_ok = bool(
        os.getenv("GOOGLE_API_KEY", "")
        and os.getenv("GOOGLE_API_KEY") != "your_google_gemini_api_key_here"
    )

    if not api_ok:
        st.warning("⚠️ GOOGLE_API_KEY not configured.\nEdit `.env` to continue.", icon="🔑")

    analyze_clicked = st.button(
        "🚀 Run Analysis",
        disabled=(st.session_state.running or not api_ok),
        use_container_width=True,
        type="primary",
    )
    st.markdown("&nbsp;")
    st.info(
        "**How it works**\n\n"
        "1. Logs are parsed & filtered by the regex engine.\n"
        "2. Three AI agents execute sequentially.\n"
        "3. A forensic report is generated.",
        icon="ℹ️",
    )


# --- Trigger analysis ------------------------------------------------------
active_log = log_input if "log_input" in dir() and log_input else ""

if analyze_clicked and active_log.strip():
    run_analysis(active_log)
    st.rerun()
elif analyze_clicked and not active_log.strip():
    st.warning("⚠️ Please paste logs or upload a file before running analysis.")


# --- Error display ---------------------------------------------------------
if st.session_state.error:
    st.error(f"❌ **Error:** {st.session_state.error}", icon="🚨")


# ---------------------------------------------------------------------------
# Results section
# ---------------------------------------------------------------------------
if st.session_state.analysis_done:
    st.markdown("---")
    st.markdown("## 🔬 Analysis Results")

    # Severity banner
    sev = st.session_state.severity
    sev_colors = {
        "Low": "#238636",
        "Medium": "#9e6a03",
        "High": "#da3633",
        "Critical": "#6e40c9",
        "Unknown": "#30363d",
    }
    banner_color = sev_colors.get(sev, "#30363d")
    st.markdown(
        f"""<div style="background:{banner_color};border-radius:8px;padding:0.75rem 1.25rem;
        margin-bottom:1rem;font-size:1.1rem;font-weight:700;letter-spacing:1px;">
        🚨 THREAT SEVERITY: {sev.upper()}
        </div>""",
        unsafe_allow_html=True,
    )

    # Metrics row
    m1, m2, m3 = st.columns(3)
    m1.metric("📄 Total Log Lines",     st.session_state.parsed_count)
    m2.metric("🚩 Suspicious Entries",  st.session_state.suspicious_count)
    m3.metric("⚠️  Severity Level",     sev)

    st.markdown("---")

    # Agent thought-process expanders
    st.markdown("### 🤖 Agent Reasoning Trace")

    with st.expander("🔍 Watchdog Agent — IoC Extraction", expanded=True):
        thought = st.session_state.step_watchdog or ""
        if thought.strip():
            st.code(thought, language="text")
        else:
            st.info("No verbose output captured for this stage.")

    with st.expander("🧠 IntelAnalyst Agent — MITRE ATT&CK Mapping", expanded=False):
        thought = st.session_state.step_intel or ""
        if thought.strip():
            st.code(thought, language="text")
        else:
            st.info("No verbose output captured for this stage.")

    with st.expander("🚨 Responder Agent — Mitigation & Report Generation", expanded=False):
        thought = st.session_state.step_responder or ""
        if thought.strip():
            st.code(thought, language="text")
        else:
            st.info("No verbose output captured for this stage.")

    st.markdown("---")

    # Final report
    st.markdown("### 📋 Forensic Incident Report & Mitigation Commands")
    report_text = st.session_state.final_report or ""
    st.markdown(report_text, unsafe_allow_html=False)

    # Download button
    st.download_button(
        label="⬇️ Download Full Report (.md)",
        data=report_text.encode("utf-8"),
        file_name="aegisagent_incident_report.md",
        mime="text/markdown",
        use_container_width=False,
    )

elif st.session_state.running:
    st.info("⏳ Analysis in progress… Please wait.", icon="🔄")

else:
    # Idle state — instructional placeholder
    st.markdown("---")
    st.markdown(
        """<div style="background:#161b22;border:1px solid #30363d;border-radius:10px;
        padding:2rem;text-align:center;color:#8b949e;">
        <h3 style="color:#58a6ff;">Awaiting Log Input</h3>
        <p>Paste server logs or upload a file, then click <b>🚀 Run Analysis</b>.</p>
        <p style="font-size:0.85rem;">Supports Apache / Nginx Combined Log Format</p>
        </div>""",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.markdown("---")
st.markdown(
    '<p style="text-align:center;font-size:0.75rem;color:#484f58;">'
    "AegisAgent · IBM SkillsBuild Capstone · Built with CrewAI, Gemini & Streamlit"
    "</p>",
    unsafe_allow_html=True,
)
