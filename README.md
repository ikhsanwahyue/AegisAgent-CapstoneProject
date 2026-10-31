# 🛡️ AegisAgent — Autonomous Cyber Defense System

> **IBM SkillsBuild Vibe Coding — Capstone Project**
> A multi-agent AI platform for automated cybersecurity incident response.

---

## Overview

AegisAgent is a full-stack, agentic AI platform that automates the first three tiers of a Security Operations Center (SOC) workflow. It ingests raw server logs, extracts Indicators of Compromise (IoCs), maps them to MITRE ATT&CK techniques, assigns severity levels, generates firewall mitigation scripts, and produces a formal forensic incident report — all driven by a three-agent CrewAI pipeline backed by Google Gemini.

```
Raw Logs  →  Log Parser  →  Watchdog Agent  →  IntelAnalyst Agent  →  Responder Agent  →  Report
```

---

## Architecture

```
aegis-agent/
│
├── .env                  # API key configuration (not committed to git)
├── requirements.txt      # Python dependencies
├── README.md             # This file
│
├── app.py                # Streamlit SOC Dashboard (entry point)
├── agents.py             # CrewAI Agent definitions (Watchdog, IntelAnalyst, Responder)
├── tasks.py              # CrewAI Task definitions (sequential pipeline)
│
└── utils/
    ├── __init__.py       # Package exports
    └── log_parser.py     # Regex log parser & suspicious-entry filter
```

---

## Agent Pipeline

| # | Agent | Role | Output |
|---|-------|------|--------|
| 1 | **Watchdog** | Tier-1 SOC Analyst | Structured IoC Inventory |
| 2 | **IntelAnalyst** | Threat Intelligence Specialist | MITRE ATT&CK Brief + Severity |
| 3 | **Responder** | Incident Commander | Firewall Script + Forensic Report |

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.10+ |
| Multi-Agent Orchestration | [CrewAI](https://docs.crewai.com/) |
| LLM | Google Gemini 2.0 Flash via `langchain-google-genai` |
| Frontend / UI | [Streamlit](https://streamlit.io/) |
| Log Parsing | Python `re` (regex) |
| Configuration | `python-dotenv` |

---

## Prerequisites

- Python 3.10 or higher
- A **Google Gemini API key** — get one free at [Google AI Studio](https://aistudio.google.com/app/apikey)

---

## Setup & Installation

### 1. Clone / navigate to the project directory

```bash
cd aegis-agent
```

### 2. Create and activate a virtual environment (recommended)

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure your API key

Open `.env` and replace the placeholder value:

```dotenv
GOOGLE_API_KEY=your_actual_gemini_api_key_here
```

### 5. Launch the dashboard

```bash
streamlit run app.py
```

The dashboard will open at `http://localhost:8501`.

---

## Usage

1. **Paste logs** into the text area **or** upload a `.log` / `.txt` file.
2. Click **🚀 Run Analysis**.
3. Monitor the three-agent pipeline in real time through the **Agent Reasoning Trace** expanders.
4. Review the **Forensic Incident Report** and copy the ready-to-run **firewall mitigation commands**.
5. Download the full Markdown report using the **⬇️ Download** button.

### Sample log format (Apache/Nginx Combined Log Format)

```
192.168.1.105 - - [28/Oct/2026:03:14:22 +0000] "POST /admin/login HTTP/1.1" 401 512 "-" "python-requests/2.28"
10.0.0.47 - - [28/Oct/2026:03:15:01 +0000] "GET /index.php?id=1' OR '1'='1 HTTP/1.1" 500 1024 "-" "sqlmap/1.7"
```

A built-in **"Load Sample Logs"** button is provided for quick testing.

---

## Log Parser Details

The `utils/log_parser.py` module:

- **Parses** Apache/Nginx Combined Log Format using a single compiled regex.
- **Extracts** IP, timestamp, HTTP method, path, query parameters, and status code.
- **Filters** entries keeping only those with anomaly signals:
  - Authentication failures (401, 403)
  - Server errors (5xx)
  - Client errors (4xx)
  - SQL injection patterns
  - XSS patterns
  - Directory traversal patterns
  - Unusual HTTP methods (PUT, DELETE, TRACE, CONNECT)
- **Formats** filtered entries into a compact, token-efficient string to stay within LLM context window limits.

---

## Severity Levels

| Level | Indicator |
|-------|-----------|
| 🟢 **Low** | Isolated anomalies, no confirmed exploitation |
| 🟡 **Medium** | Reconnaissance or failed attack attempts |
| 🔴 **High** | Confirmed exploitation or data exfiltration evidence |
| 🟣 **Critical** | Active breach, lateral movement, or ransomware indicators |

---

## Security Notes

- Never commit your `.env` file to version control. It is listed in `.gitignore` by default.
- The generated `iptables` rules are provided as a **starting point** — review them before applying to production systems.
- This tool is for educational and defensive security purposes only.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*AegisAgent · IBM SkillsBuild Capstone · Powered by CrewAI & Google Gemini*
