"""Drift detection: compare a server's current tools against an approved lockfile.

The headline case is the "rug-pull": a tool that was approved with a benign description
silently changes its description (or schema) in a later session to hijack the agent. Such
a change is flagged HIGH because the user already trusted that tool name.
"""

from __future__ import annotations

from collections.abc import Iterable

from .fingerprint import fingerprint_server
from .lockfile import LockFile
from .models import DriftEntry, DriftKind, DriftReport, Severity, ToolFingerprint, ToolSchema


def _split_change(old: ToolFingerprint | None, locked_desc: str, new_desc: str) -> DriftKind:
    """Decide whether a changed hash is a description change or a broader schema change."""
    if locked_desc != new_desc:
        return DriftKind.DESCRIPTION_CHANGED
    return DriftKind.SCHEMA_CHANGED


def compare_fingerprints(current: dict[str, ToolFingerprint], lock: LockFile) -> DriftReport:
    """Compare current fingerprints to the lockfile and produce a DriftReport."""
    entries: list[DriftEntry] = []

    locked_names = set(lock.tools)
    current_names = set(current)

    # New tools: appeared since approval. Untrusted by definition -> MEDIUM.
    for name in sorted(current_names - locked_names):
        entries.append(
            DriftEntry(
                tool=name,
                kind=DriftKind.NEW,
                severity=Severity.MEDIUM,
                detail="tool not present in lockfile (added after approval)",
                new_hash=current[name].hash,
            )
        )

    # Removed tools: disappeared since approval -> LOW (availability, not hijack).
    for name in sorted(locked_names - current_names):
        entries.append(
            DriftEntry(
                tool=name,
                kind=DriftKind.REMOVED,
                severity=Severity.LOW,
                detail="tool present in lockfile but missing from server",
                old_hash=lock.tools[name].hash,
            )
        )

    # Shared tools: compare hashes. A changed hash on an approved tool is the rug-pull.
    for name in sorted(locked_names & current_names):
        locked = lock.tools[name]
        cur = current[name]
        if locked.hash == cur.hash:
            continue
        kind = _split_change(None, locked.description, cur.description)
        if kind == DriftKind.DESCRIPTION_CHANGED:
            detail = "description changed after approval (possible rug-pull)"
            severity = Severity.HIGH
        else:
            detail = "input schema changed after approval"
            severity = Severity.HIGH
        entries.append(
            DriftEntry(
                tool=name,
                kind=kind,
                severity=severity,
                detail=detail,
                old_hash=locked.hash,
                new_hash=cur.hash,
            )
        )

    return DriftReport(entries=entries)


def detect_drift(tools: Iterable[ToolSchema], lock: LockFile) -> DriftReport:
    """Fingerprint current tools and compare them to the lockfile."""
    current = fingerprint_server(tools)
    return compare_fingerprints(current, lock)
