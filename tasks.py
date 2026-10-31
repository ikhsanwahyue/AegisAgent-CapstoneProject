"""
tasks.py
--------
AegisAgent — CrewAI Task definitions.

Three sequential tasks form the incident-response pipeline:

    extract_anomalies_task  →  classify_threat_task  →  generate_mitigation_task

Each task's output becomes the context for the next, creating a clean
chain-of-thought that mirrors a real SOC triage workflow.
"""

from crewai import Task
from agents import (
    get_watchdog_agent,
    get_intel_analyst_agent,
    get_responder_agent,
)


def build_tasks(filtered_log_text: str) -> tuple[Task, Task, Task]:
    """Construct and return the three pipeline tasks with live log data injected.

    Args:
        filtered_log_text: Pre-processed log string from
                           ``utils.log_parser.format_for_llm()``.

    Returns:
        Tuple of (extract_task, classify_task, mitigation_task) ready to be
        passed to a ``crewai.Crew`` instance.
    """
    watchdog = get_watchdog_agent()
    intel = get_intel_analyst_agent()
    responder = get_responder_agent()

    # ------------------------------------------------------------------
    # Task 1 – IoC Extraction
    # ------------------------------------------------------------------
    extract_anomalies_task = Task(
        description=(
            "You are receiving the following pre-filtered server log entries. "
            "Each line has already been flagged by an automated parser as "
            "potentially suspicious.  Your job is to perform a thorough triage:\n\n"
            "```\n"
            f"{filtered_log_text}\n"
            "```\n\n"
            "Instructions:\n"
            "1. Identify and list every unique suspicious IP address.\n"
            "2. Highlight repeated authentication failure sequences (brute-force signals).\n"
            "3. Flag any request paths or parameters containing injection patterns "
            "   (SQL, XSS, path traversal).\n"
            "4. Note any unusual HTTP methods (PUT, DELETE, TRACE, OPTIONS, CONNECT).\n"
            "5. Identify volumetric anomalies (same IP making many requests).\n"
            "6. Produce a structured **IoC Inventory** with a numbered list of findings.\n\n"
            "Format your output as:\n"
            "## IoC Inventory\n"
            "### Suspicious IPs\n"
            "### Auth Failure Patterns\n"
            "### Injection Signatures\n"
            "### Unusual Methods\n"
            "### Volumetric Anomalies\n"
            "### Additional Observations\n"
        ),
        expected_output=(
            "A clearly structured Markdown IoC Inventory with separate sections "
            "for each category of finding, including specific log line references "
            "where applicable."
        ),
        agent=watchdog,
    )

    # ------------------------------------------------------------------
    # Task 2 – Threat Classification & MITRE ATT&CK Mapping
    # ------------------------------------------------------------------
    classify_threat_task = Task(
        description=(
            "Using the IoC Inventory produced by the Watchdog analyst, "
            "perform a comprehensive threat intelligence assessment.\n\n"
            "Instructions:\n"
            "1. Map each IoC category to the relevant MITRE ATT&CK Tactic "
            "   (e.g., Initial Access, Credential Access, Impact) and Technique ID "
            "   (e.g., T1190 – Exploit Public-Facing Application).\n"
            "2. Classify the overall attack type: choose from Brute Force, "
            "   SQL Injection, XSS, Directory Traversal, DDoS, Reconnaissance, "
            "   Lateral Movement, Command Injection, or Compound Attack.\n"
            "3. Assign a Severity Level (Low / Medium / High / Critical) with "
            "   a brief justification for the chosen level.\n"
            "4. Estimate potential business impact (data breach, service disruption, etc.).\n"
            "5. List any threat actors or campaigns (APT groups) known to use "
            "   these techniques if applicable.\n\n"
            "Format your output as:\n"
            "## Threat Intelligence Brief\n"
            "### MITRE ATT&CK Mapping\n"
            "### Attack Classification\n"
            "### Severity Assessment\n"
            "### Business Impact Estimation\n"
            "### Known Threat Actors / Campaigns\n"
        ),
        expected_output=(
            "A Markdown Threat Intelligence Brief with ATT&CK technique IDs, "
            "a clear severity rating with justification, and estimated impact."
        ),
        agent=intel,
        context=[extract_anomalies_task],
    )

    # ------------------------------------------------------------------
    # Task 3 – Mitigation Scripting & Forensic Report
    # ------------------------------------------------------------------
    generate_mitigation_task = Task(
        description=(
            "You are the Incident Commander.  Using all findings from the "
            "Watchdog and IntelAnalyst, produce two deliverables:\n\n"
            "**Deliverable A – Firewall Mitigation Script**\n"
            "Write a complete, commented shell script that:\n"
            "- Blocks every identified malicious IP using iptables INPUT DROP rules.\n"
            "- Applies rate-limiting rules (iptables --limit) for brute-force IPs.\n"
            "- Adds ufw deny rules as an alternative for Ubuntu/Debian systems.\n"
            "- Includes a rule to block the specific attack vectors identified "
            "  (e.g., block SQL keyword patterns if a WAF is present).\n"
            "- Ends with a command to save iptables rules persistently.\n\n"
            "**Deliverable B – Forensic Incident Report**\n"
            "Author a formal report with the following sections:\n"
            "1. Executive Summary\n"
            "2. Incident Timeline\n"
            "3. Affected Systems & Assets\n"
            "4. Threat Actor Profile & TTPs\n"
            "5. Detailed Findings (reference IoC Inventory & Threat Brief)\n"
            "6. Mitigation Actions Taken\n"
            "7. Recommendations & Hardening Measures\n"
            "8. Appendix – Raw IoC List\n\n"
            "Combine both deliverables in your final output, clearly separated."
        ),
        expected_output=(
            "A complete Markdown document containing: (1) a commented "
            "bash firewall mitigation script in a fenced code block, and "
            "(2) a formal Forensic Incident Report with all eight sections."
        ),
        agent=responder,
        context=[extract_anomalies_task, classify_threat_task],
    )

    return extract_anomalies_task, classify_threat_task, generate_mitigation_task
