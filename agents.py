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
# agents.py
# ---------
# AegisAgent — Agent definitions using LangChain + Google Gemini.
#
# CrewAI requires Python <3.14 and is incompatible with this environment.
# This module replicates the exact same three-agent SOC hierarchy using
# plain LangChain ChatPromptTemplate + ChatGoogleGenerativeAI chains.
# Each agent is a callable function: agent(input_text: str) -> str
#
# Agent Hierarchy
# ~~~~~~~~~~~~~~~
# Tier 1 – Watchdog       : raw log triage & IoC extraction
# Tier 2 – IntelAnalyst   : threat classification & MITRE ATT&CK mapping
# Tier 3 – Responder      : mitigation scripting & forensic report authoring
# ---------------------------------------------------------------------------

import os
import time
import re as _re
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

load_dotenv()

_api_key = os.getenv("GOOGLE_API_KEY", "")
if not _api_key or _api_key == "your_google_gemini_api_key_here":
    raise EnvironmentError(
        "GOOGLE_API_KEY is not set. "
        "Add your Gemini API key to the .env file before running AegisAgent."
    )

# Shared LLM — temperature=0 for deterministic security reasoning
_llm = ChatGoogleGenerativeAI(
    model="gemini-1.5-flash",
    google_api_key=_api_key,
    temperature=0.0,
)

_parser = StrOutputParser()


def _invoke_with_retry(chain, payload: dict, max_retries: int = 5) -> str:
    """Invoke a LangChain chain with automatic retry on 429 rate-limit errors.

    Parses the retry_delay from the error message when available; otherwise
    uses exponential backoff (15s, 30s, 60s, …).

    Args:
        chain:       A compiled LangChain chain (prompt | llm | parser).
        payload:     Dict passed to chain.invoke().
        max_retries: Maximum number of retry attempts before re-raising.

    Returns:
        The string output from the chain.
    """
    delay = 15  # initial wait in seconds
    for attempt in range(max_retries + 1):
        try:
            return chain.invoke(payload)
        except Exception as exc:
            msg = str(exc)
            # Only retry on HTTP 429 quota errors
            if "429" not in msg and "quota" not in msg.lower():
                raise
            if attempt == max_retries:
                raise

            # Try to extract the suggested retry_delay from the error body
            match = _re.search(r'retry[_ ]?delay.*?(\d+)', msg, _re.IGNORECASE)
            wait = int(match.group(1)) + 2 if match else delay

            print(f"[AegisAgent] Rate limit hit — waiting {wait}s "
                  f"(attempt {attempt + 1}/{max_retries})…")
            time.sleep(wait)
            delay = min(delay * 2, 120)  # cap at 120s


def _make_chain(system_prompt: str):
    """Return a simple (human_input -> str) LangChain chain."""
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", "{input}"),
    ])
    return prompt | _llm | _parser


# ---------------------------------------------------------------------------
# Tier-1: Watchdog — IoC Extraction
# ---------------------------------------------------------------------------

_WATCHDOG_SYSTEM = """You are an elite Tier-1 SOC Analyst with 10 years of \
blue-team experience in network intrusion detection. You have an eagle eye for \
spotting the earliest signals of an attack in raw log data and you document \
your findings with military precision.

Your task: Scan the provided pre-filtered server log entries and extract every \
Indicator of Compromise (IoC).

Instructions:
1. Identify and list every unique suspicious IP address.
2. Highlight repeated authentication failure sequences (brute-force signals).
3. Flag any request paths or parameters containing injection patterns (SQL, XSS, path traversal).
4. Note any unusual HTTP methods (PUT, DELETE, TRACE, OPTIONS, CONNECT).
5. Identify volumetric anomalies (same IP making many requests).
6. Produce a structured IoC Inventory with a numbered list of findings.

Format your output as:
## IoC Inventory
### Suspicious IPs
### Auth Failure Patterns
### Injection Signatures
### Unusual Methods
### Volumetric Anomalies
### Additional Observations"""

_watchdog_chain = _make_chain(_WATCHDOG_SYSTEM)


def run_watchdog(filtered_log_text: str) -> str:
    """Tier-1 Watchdog Agent: extracts IoCs from filtered log data.

    Args:
        filtered_log_text: Output of utils.log_parser.format_for_llm().

    Returns:
        Markdown IoC Inventory string.
    """
    return _invoke_with_retry(_watchdog_chain, {"input": filtered_log_text})


# ---------------------------------------------------------------------------
# Tier-2: IntelAnalyst — MITRE ATT&CK Mapping & Threat Classification
# ---------------------------------------------------------------------------

_INTEL_SYSTEM = """You are a seasoned Threat Intelligence Specialist with deep \
expertise in the MITRE ATT&CK framework and global threat-actor TTPs. You have \
analysed hundreds of APT campaigns and can instantly correlate raw IoCs to \
known adversarial patterns.

Your task: Using the IoC Inventory provided, perform a comprehensive threat \
intelligence assessment.

Instructions:
1. Map each IoC category to the relevant MITRE ATT&CK Tactic (e.g., Initial \
Access, Credential Access, Impact) and Technique ID (e.g., T1190).
2. Classify the overall attack type: Brute Force, SQL Injection, XSS, Directory \
Traversal, DDoS, Reconnaissance, Lateral Movement, Command Injection, or Compound Attack.
3. Assign a Severity Level (Low / Medium / High / Critical) with a brief justification.
4. Estimate potential business impact (data breach, service disruption, etc.).
5. List any known threat actors or campaigns (APT groups) that use these techniques.

Format your output as:
## Threat Intelligence Brief
### MITRE ATT&CK Mapping
### Attack Classification
### Severity Assessment
### Business Impact Estimation
### Known Threat Actors / Campaigns"""

_intel_chain = _make_chain(_INTEL_SYSTEM)


def run_intel_analyst(ioc_inventory: str) -> str:
    """Tier-2 IntelAnalyst Agent: maps IoCs to MITRE ATT&CK and assigns severity.

    Args:
        ioc_inventory: Output of run_watchdog().

    Returns:
        Markdown Threat Intelligence Brief string.
    """
    return _invoke_with_retry(_intel_chain, {"input": ioc_inventory})


# ---------------------------------------------------------------------------
# Tier-3: Responder — Mitigation Script + Forensic Report
# ---------------------------------------------------------------------------

_RESPONDER_SYSTEM = """You are a battle-hardened Incident Commander who has led \
the response to nation-state attacks, ransomware campaigns, and large-scale DDoS \
events. You translate intelligence into decisive, executable remediation steps and \
communicate findings clearly to both technical and executive stakeholders.

Your task: Using the IoC Inventory and Threat Intelligence Brief provided, produce \
two deliverables:

**Deliverable A – Firewall Mitigation Script**
Write a complete, commented bash script that:
- Blocks every identified malicious IP using iptables INPUT DROP rules.
- Applies rate-limiting rules (iptables --limit) for brute-force IPs.
- Adds ufw deny rules as an alternative for Ubuntu/Debian systems.
- Ends with a command to save iptables rules persistently (iptables-save).

**Deliverable B – Forensic Incident Report**
Author a formal report with the following sections:
1. Executive Summary
2. Incident Timeline
3. Affected Systems & Assets
4. Threat Actor Profile & TTPs
5. Detailed Findings (reference IoC Inventory & Threat Brief)
6. Mitigation Actions Taken
7. Recommendations & Hardening Measures
8. Appendix – Raw IoC List

Combine both deliverables in your final output, clearly separated."""

_responder_chain = _make_chain(_RESPONDER_SYSTEM)


def run_responder(ioc_inventory: str, threat_brief: str) -> str:
    """Tier-3 Responder Agent: generates firewall script + forensic report.

    Args:
        ioc_inventory: Output of run_watchdog().
        threat_brief:  Output of run_intel_analyst().

    Returns:
        Markdown string with firewall script and full forensic report.
    """
    combined = (
        "## IoC Inventory (from Watchdog)\n\n"
        f"{ioc_inventory}\n\n"
        "---\n\n"
        "## Threat Intelligence Brief (from IntelAnalyst)\n\n"
        f"{threat_brief}"
    )
    return _invoke_with_retry(_responder_chain, {"input": combined})
