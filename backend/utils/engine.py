"""Utility to return the global MonitoringManager instance started by `app.py`.

This handles the common case where `app.py` was executed as `__main__` so
importing `app` fails. It tries multiple fallbacks to reliably return the
monitoring manager used by the running process.
"""
from typing import Optional
import sys


def get_monitoring_manager() -> Optional[object]:
    """Return the monitoring_manager instance if available, else None.

    Prefer the already-executing `__main__` module to avoid re-importing
    `app.py` (which would create a second MonitoringManager instance).
    """
    try:
        main = sys.modules.get("__main__")
        if main is not None:
            mm = getattr(main, "monitoring_manager", None)
            if mm is not None:
                return mm
    except Exception:
        pass

    try:
        # If the app module has already been imported, use it without forcing
        # a new import, otherwise attempt a gentle import.
        app_mod = sys.modules.get("app")
        if app_mod is None:
            import importlib
            try:
                app_mod = importlib.import_module("app")
            except Exception:
                app_mod = None
        if app_mod is not None:
            mm = getattr(app_mod, "monitoring_manager", None)
            if mm is not None:
                return mm
    except Exception:
        pass

    return None
