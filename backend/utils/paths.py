"""Deterministic filesystem locations for ShadowPulse runtime resources."""

from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = PROJECT_ROOT / "backend"
CONFIG_PATH = BACKEND_ROOT / "shadowpulse.conf"
LOG_DIR = BACKEND_ROOT / "logs"
EXPORT_DIR = BACKEND_ROOT / "exports"
REPORT_DIR = BACKEND_ROOT / "reports"
CAPTURE_DIR = BACKEND_ROOT / "captures"


def resolve_backend_path(value: str | Path) -> Path:
    """Resolve a configured resource path without depending on process CWD."""
    path = Path(value).expanduser()
    return path if path.is_absolute() else BACKEND_ROOT / path


def ensure_runtime_directories() -> None:
    """Create runtime directories when the application initializes."""
    for directory in (LOG_DIR, EXPORT_DIR, REPORT_DIR, CAPTURE_DIR):
        directory.mkdir(parents=True, exist_ok=True)
