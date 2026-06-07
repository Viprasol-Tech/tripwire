from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from tripwire import __version__
from tripwire.cli import app
from tripwire.models import Severity

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_demo_runs_and_blocks() -> None:
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 0
    assert "BLOCKED rug-pull" in result.stdout
    assert "BLOCKED poison" in result.stdout


def test_approve_then_scan_clean(tmp_path: Path) -> None:
    lock = tmp_path / ".tripwire-lock.json"
    approve = runner.invoke(app, ["approve", "--sample", "clean", "--lock", str(lock)])
    assert approve.exit_code == 0
    assert lock.exists()

    scan = runner.invoke(app, ["scan", "--sample", "clean", "--lock", str(lock)])
    assert scan.exit_code == 0
    assert "ALLOWED" in scan.stdout


def test_scan_rugpull_blocks(tmp_path: Path) -> None:
    lock = tmp_path / ".tripwire-lock.json"
    runner.invoke(app, ["approve", "--sample", "clean", "--lock", str(lock)])
    scan = runner.invoke(app, ["scan", "--sample", "rugpull", "--lock", str(lock)])
    assert scan.exit_code == 1
    assert "BLOCKED" in scan.stdout


def test_scan_unknown_sample() -> None:
    result = runner.invoke(app, ["scan", "--sample", "nope"])
    assert result.exit_code == 2


def test_severity_ordering() -> None:
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.NONE
    assert Severity.HIGH >= Severity.HIGH
    assert Severity.LOW <= Severity.MEDIUM
