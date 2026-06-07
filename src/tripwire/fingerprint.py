"""Deterministic fingerprinting of MCP tool schemas.

A fingerprint is a SHA-256 over a canonical JSON encoding of the tool. Canonical means
keys are sorted recursively and separators are fixed, so logically-equal schemas always
produce the same hash regardless of key order or whitespace.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any

from .models import ToolFingerprint, ToolSchema


def canonical_json(value: Any) -> str:
    """Encode a value to canonical JSON (sorted keys, compact separators)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fingerprint_tool(tool: ToolSchema) -> ToolFingerprint:
    """Compute a stable fingerprint for a single tool schema."""
    payload = {
        "name": tool.name,
        "description": tool.description,
        "input_schema": tool.input_schema,
    }
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return ToolFingerprint(name=tool.name, hash=digest, description=tool.description)


def fingerprint_server(tools: Iterable[ToolSchema]) -> dict[str, ToolFingerprint]:
    """Fingerprint a whole server: a mapping of tool name -> fingerprint.

    Raises:
        ValueError: if two tools share the same name (ambiguous server state).
    """
    result: dict[str, ToolFingerprint] = {}
    for tool in tools:
        if tool.name in result:
            raise ValueError(f"duplicate tool name in server schema: {tool.name!r}")
        result[tool.name] = fingerprint_tool(tool)
    return result


def hash_map(tools: Iterable[ToolSchema]) -> dict[str, str]:
    """Convenience: mapping of tool name -> hash string."""
    return {name: fp.hash for name, fp in fingerprint_server(tools).items()}
