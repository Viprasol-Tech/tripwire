from __future__ import annotations

import pytest

from tripwire.fingerprint import (
    canonical_json,
    fingerprint_server,
    fingerprint_tool,
    hash_map,
)
from tripwire.models import ToolSchema


def _tool(desc: str = "Adds two numbers.") -> ToolSchema:
    return ToolSchema(
        name="add",
        description=desc,
        input_schema={"type": "object", "properties": {"a": {"type": "number"}}},
    )


def test_canonical_json_sorts_keys() -> None:
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_fingerprint_is_deterministic() -> None:
    a = fingerprint_tool(_tool())
    b = fingerprint_tool(_tool())
    assert a.hash == b.hash
    assert len(a.hash) == 64  # sha256 hex


def test_fingerprint_stable_under_key_reordering() -> None:
    t1 = ToolSchema(name="x", description="d", input_schema={"a": 1, "b": 2})
    t2 = ToolSchema(name="x", description="d", input_schema={"b": 2, "a": 1})
    assert fingerprint_tool(t1).hash == fingerprint_tool(t2).hash


def test_fingerprint_changes_on_description() -> None:
    a = fingerprint_tool(_tool("Adds two numbers."))
    b = fingerprint_tool(_tool("Adds two numbers and emails them."))
    assert a.hash != b.hash


def test_fingerprint_changes_on_schema() -> None:
    a = fingerprint_tool(ToolSchema(name="x", description="d", input_schema={"a": 1}))
    b = fingerprint_tool(ToolSchema(name="x", description="d", input_schema={"a": 2}))
    assert a.hash != b.hash


def test_fingerprint_changes_on_name() -> None:
    a = fingerprint_tool(ToolSchema(name="x", description="d"))
    b = fingerprint_tool(ToolSchema(name="y", description="d"))
    assert a.hash != b.hash


def test_fingerprint_server_maps_names() -> None:
    tools = [ToolSchema(name="a"), ToolSchema(name="b")]
    fps = fingerprint_server(tools)
    assert set(fps) == {"a", "b"}
    assert fps["a"].name == "a"


def test_fingerprint_server_rejects_duplicates() -> None:
    with pytest.raises(ValueError, match="duplicate tool name"):
        fingerprint_server([ToolSchema(name="a"), ToolSchema(name="a")])


def test_hash_map_returns_strings() -> None:
    hm = hash_map([ToolSchema(name="a"), ToolSchema(name="b")])
    assert set(hm) == {"a", "b"}
    assert all(isinstance(v, str) and len(v) == 64 for v in hm.values())
