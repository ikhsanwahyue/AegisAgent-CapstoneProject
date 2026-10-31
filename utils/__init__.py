import sys
try:
    import pkg_resources  # noqa: F401 — already available, nothing to do
except ImportError:
    try:
        import setuptools as _st
        sys.modules['pkg_resources'] = _st
    except ImportError:
        from types import ModuleType as _M
        sys.modules['pkg_resources'] = _M('pkg_resources')

# ---------------------------------------------------------------------------
# utils/__init__.py
# -----------------
# AegisAgent Utilities Package.
# Exports the three public log-parser helpers used by app.py and tasks.py.
# ---------------------------------------------------------------------------

from .log_parser import parse_logs, filter_suspicious_logs, format_for_llm

__all__ = ["parse_logs", "filter_suspicious_logs", "format_for_llm"]
