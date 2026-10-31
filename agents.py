"""
agents.py
---------
AegisAgent — CrewAI Agent definitions.

Three tiered SOC agents are defined here, each backed by Google Gemini
via `langchain-google-genai`.  All agents use temperature=0.0 for
deterministic, reproducible security analysis.

Agent Hierarchy
~~~~~~~~~~~~~~~
Tier 1 – Watchdog       : raw log triage & IoC extraction
Tier 2 – IntelAnalyst   : threat classification & MITRE ATT&CK mapping
Tier 3 – Responder      : mitigation scripting & forensic report authoring
"""

import os
from dotenv import load_dotenv
from crewai import Agent
from langchain_google_genai import ChatGoogleGenerativeAI

# ---------------------------------------------------------------------------
# Environment bootstrap
# ---------------------------------------------------------------------------

load_dotenv()

_api_key = os.getenv("GOOGLE_API_KEY", "")
if not _api_key or _api_key == "your_google_gemini_api_key_here":
    raise EnvironmentError(
        "GOOGLE_API_KEY is not set. "
        "Add your Gemini API key to the .env file before running AegisAgent."
    )

# ---------------------------------------------------------------------------
# Shared LLM instance (temperature=0 for deterministic security reasoning)
# ---------------------------------------------------------------------------

_llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash",
    google_api_key=_api_key,
    temperature=0.0,
    convert_system_message_to_human=True,
)


# ---------------------------------------------------------------------------
# Agent definitions
# ---------------------------------------------------------------------------

def get_watchdog_agent() -> Agent:
    """Tier-1 SOC Analyst — Watchdog.

    Responsibilities:
        - Ingest parsed & filtered log data.
        - Identify and enumerate all Indicators of Compromise (IoCs):
          suspicious IPs, anomalous request patterns, repeated auth failures,
          injection signatures, unexpected HTTP methods, etc.
        - Produce a structured IoC inventory for the IntelAnalyst.
    """
    return Agent(
        role="Tier-1 SOC Analyst (Watchdog)",
        goal=(
            "Scan the provided server logs and extract every Indicator of "
            "Compromise (IoC). Enumerate suspicious IP addresses, repeated "
            "authentication failures, injection signatures, and abnormal HTTP "
            "patterns. Produce a clear, numbered IoC inventory."
        ),
        backstory=(
            "You are an elite Tier-1 SOC Analyst with 10 years of blue-team "
            "experience in network intrusion detection.  You have an eagle eye "
            "for spotting the earliest signals of an attack in raw log data and "
            "you document your findings with military precision."
        ),
        llm=_llm,
        verbose=True,
        allow_delegation=False,
        max_iter=3,
    )


def get_intel_analyst_agent() -> Agent:
    """Tier-2 Threat Intelligence Specialist — IntelAnalyst.

    Responsibilities:
        - Receive the IoC inventory from the Watchdog.
        - Map each IoC to a MITRE ATT&CK Tactic / Technique.
        - Classify the threat vector (Brute Force, SQL Injection, XSS,
          DDoS, Reconnaissance, Lateral Movement, etc.).
        - Assign a severity level: Low | Medium | High | Critical.
        - Output a structured Threat Intelligence Brief.
    """
    return Agent(
        role="Threat Intelligence Specialist (IntelAnalyst)",
        goal=(
            "Map the supplied IoCs to MITRE ATT&CK tactics and techniques. "
            "Classify each threat vector (e.g., Brute Force — T1110, "
            "SQL Injection — T1190, DDoS — T1498) and assign a severity level "
            "(Low / Medium / High / Critical) with justification."
        ),
        backstory=(
            "You are a seasoned Threat Intelligence Specialist with deep "
            "expertise in the MITRE ATT&CK framework and global threat-actor "
            "TTPs.  You have analysed hundreds of APT campaigns and can "
            "instantly correlate raw IoCs to known adversarial patterns."
        ),
        llm=_llm,
        verbose=True,
        allow_delegation=False,
        max_iter=3,
    )


def get_responder_agent() -> Agent:
    """Tier-3 Incident Commander — Responder.

    Responsibilities:
        - Receive the Threat Intelligence Brief.
        - Draft immediate mitigation: iptables / ufw firewall rules targeting
          identified malicious IPs and attack vectors.
        - Compose a formal, structured Forensic Incident Report suitable for
          CISO-level briefing and regulatory compliance.
    """
    return Agent(
        role="Incident Commander (Responder)",
        goal=(
            "Draft actionable firewall mitigation scripts (iptables/ufw) for "
            "every identified threat and compile a professional Forensic "
            "Incident Report that covers: Executive Summary, Timeline, "
            "Affected Assets, Threat Classification, Mitigation Actions, and "
            "Recommendations."
        ),
        backstory=(
            "You are a battle-hardened Incident Commander who has led the "
            "response to nation-state attacks, ransomware campaigns, and large-"
            "scale DDoS events.  You translate intelligence into decisive, "
            "executable remediation steps and communicate findings clearly to "
            "both technical and executive stakeholders."
        ),
        llm=_llm,
        verbose=True,
        allow_delegation=False,
        max_iter=3,
    )
