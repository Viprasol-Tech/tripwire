from __future__ import annotations

from pathlib import Path

import pytest

from tripwire.lockfile import LockFile, default_lock_path
from tripwire.models import ToolSchema
from tripwire.samples import clean_server


def test_lockfile_round_trip(tmp_path: Path) -> None:
    lock = LockFile.from_tools(clean_server(), server="demo")
    path = lock.save(tmp_path / ".tripwire-lock.json")
    assert path.exists()

    loaded = LockFile.load(path)
    assert loaded.server == "demo"
    assert set(loaded.tools) == {"get_weather", "search_docs", "add_numbers"}
    for name, entry in loaded.tools.items():
        assert entry.hash == lock.tools[name].hash


def test_lockfile_from_tools_records_descriptions() -> None:
    lock = LockFile.from_tools([ToolSchema(name="a", description="hello")])
    assert lock.tools["a"].description == "hello"


def test_lockfile_load_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        LockFile.load(tmp_path / "nope.json")


def test_lockfile_load_bad_json_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        LockFile.load(bad)


def test_lockfile_version_default() -> None:
    lock = LockFile.from_tools([ToolSchema(name="a")])
    assert lock.version == 1


def test_default_lock_path() -> None:
    assert default_lock_path("x").name == ".tripwire-lock.json"
    assert default_lock_path("x").parent == Path("x")
