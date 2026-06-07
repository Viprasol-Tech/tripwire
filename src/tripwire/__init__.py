"""tripwire: a runtime guard against MCP tool-poisoning and silent tool drift."""

from __future__ import annotations

from .drift import compare_fingerprints, detect_drift
from .fingerprint import fingerprint_server, fingerprint_tool
from .guard import StaticToolProvider, ToolProvider, TripWireBlocked, TripWireGuard
from .inject import scan_description, scan_tools
from .lockfile import LockFile
from .models import (
    DriftEntry,
    DriftKind,
    DriftReport,
    InjectionFinding,
    ScanResult,
    Severity,
    ToolFingerprint,
    ToolSchema,
)
from .policy import Decision, Policy, check, scan_result

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "Decision",
    "DriftEntry",
    "DriftKind",
    "DriftReport",
    "InjectionFinding",
    "LockFile",
    "Policy",
    "ScanResult",
    "Severity",
    "StaticToolProvider",
    "ToolFingerprint",
    "ToolProvider",
    "ToolSchema",
    "TripWireBlocked",
    "TripWireGuard",
    "check",
    "compare_fingerprints",
    "detect_drift",
    "fingerprint_server",
    "fingerprint_tool",
    "scan_description",
    "scan_result",
    "scan_tools",
]
