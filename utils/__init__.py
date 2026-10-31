"""
AegisAgent Utilities Package
Provides log parsing helpers for preprocessing raw server/network logs
before they are fed into the CrewAI agent pipeline.
"""

from .log_parser import parse_logs, filter_suspicious_logs

__all__ = ["parse_logs", "filter_suspicious_logs"]
