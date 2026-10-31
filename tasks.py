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
# tasks.py
# --------
# AegisAgent — Sequential pipeline runner.
#
# Replaces the CrewAI Task/Crew abstraction with a direct three-step
# LangChain chain pipeline:
#
#   run_watchdog()  →  run_intel_analyst()  →  run_responder()
#
# Each step's output is fed as input to the next, identical to a CrewAI
# sequential Process.
# ---------------------------------------------------------------------------

from agents import run_watchdog, run_intel_analyst, run_responder


def run_pipeline(filtered_log_text: str) -> dict[str, str]:
    """Execute the full three-agent sequential pipeline.

    Args:
        filtered_log_text: Pre-processed log string from
                           ``utils.log_parser.format_for_llm()``.

    Returns:
        Dict with keys:
            "watchdog_output"  — IoC Inventory (Tier-1)
            "intel_output"     — Threat Intelligence Brief (Tier-2)
            "responder_output" — Firewall Script + Forensic Report (Tier-3)
    """
    # Step 1 — Watchdog: IoC extraction
    watchdog_output = run_watchdog(filtered_log_text)

    # Step 2 — IntelAnalyst: MITRE mapping + severity (consumes Step 1)
    intel_output = run_intel_analyst(watchdog_output)

    # Step 3 — Responder: mitigation script + forensic report (consumes 1+2)
    responder_output = run_responder(watchdog_output, intel_output)

    return {
        "watchdog_output":  watchdog_output,
        "intel_output":     intel_output,
        "responder_output": responder_output,
    }
