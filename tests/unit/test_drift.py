from __future__ import annotations

from tripwire.drift import detect_drift
from tripwire.lockfile import LockFile
from tripwire.models import DriftKind, Severity, ToolSchema
from tripwire.samples import clean_server, rugpulled_server


def _lock() -> LockFile:
    return LockFile.from_tools(clean_server(), server="demo")


def test_no_drift_when_unchanged() -> None:
    report = detect_drift(clean_server(), _lock())
    assert not report.has_drift
    assert report.max_severity == Severity.NONE


def test_detects_new_tool() -> None:
    tools = [*clean_server(), ToolSchema(name="surprise", description="new tool")]
    report = detect_drift(tools, _lock())
    new = report.of_kind(DriftKind.NEW)
    assert len(new) == 1
    assert new[0].tool == "surprise"
    assert new[0].severity == Severity.MEDIUM


def test_detects_removed_tool() -> None:
    tools = clean_server()[:-1]  # drop add_numbers
    report = detect_drift(tools, _lock())
    removed = report.of_kind(DriftKind.REMOVED)
    assert [e.tool for e in removed] == ["add_numbers"]
    assert removed[0].severity == Severity.LOW


def test_rugpull_description_change_is_high() -> None:
    report = detect_drift(rugpulled_server(), _lock())
    changed = report.of_kind(DriftKind.DESCRIPTION_CHANGED)
    assert len(changed) == 1
    assert changed[0].tool == "get_weather"
    assert changed[0].severity == Severity.HIGH
    assert "rug-pull" in changed[0].detail


def test_schema_change_detected_and_high() -> None:
    lock = _lock()
    tools = clean_server()
    tools[2] = ToolSchema(
        name="add_numbers",
        description=tools[2].description,
        input_schema={"type": "object", "properties": {"a": {"type": "string"}}},
    )
    report = detect_drift(tools, lock)
    changed = report.of_kind(DriftKind.SCHEMA_CHANGED)
    assert len(changed) == 1
    assert changed[0].severity == Severity.HIGH


def test_drift_report_carries_hashes() -> None:
    report = detect_drift(rugpulled_server(), _lock())
    entry = report.of_kind(DriftKind.DESCRIPTION_CHANGED)[0]
    assert entry.old_hash and entry.new_hash
    assert entry.old_hash != entry.new_hash


def test_max_severity_picks_worst() -> None:
    tools = [*rugpulled_server(), ToolSchema(name="extra", description="x")]
    report = detect_drift(tools, _lock())
    assert report.max_severity == Severity.HIGH
