"""Read/write the approved-tools lockfile (.tripwire-lock.json).

The lockfile pins the fingerprints of tool schemas a user has explicitly approved. Future
sessions are compared against it to detect drift / rug-pulls.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from pydantic import BaseModel, Field

from .fingerprint import fingerprint_server
from .models import ToolFingerprint, ToolSchema

LOCKFILE_NAME = ".tripwire-lock.json"
LOCKFILE_VERSION = 1


class LockedTool(BaseModel):
    """A single approved tool entry in the lockfile."""

    name: str
    hash: str
    description: str = ""


class LockFile(BaseModel):
    """The approved-tools lockfile, schema-validated on load."""

    version: int = LOCKFILE_VERSION
    server: str = "default"
    tools: dict[str, LockedTool] = Field(default_factory=dict)

    @classmethod
    def from_tools(cls, tools: Iterable[ToolSchema], server: str = "default") -> LockFile:
        """Build a lockfile by approving the current state of a server."""
        fps = fingerprint_server(tools)
        locked = {
            name: LockedTool(name=fp.name, hash=fp.hash, description=fp.description)
            for name, fp in fps.items()
        }
        return cls(version=LOCKFILE_VERSION, server=server, tools=locked)

    @classmethod
    def from_fingerprints(
        cls, fps: dict[str, ToolFingerprint], server: str = "default"
    ) -> LockFile:
        """Build a lockfile from already-computed fingerprints."""
        locked = {
            name: LockedTool(name=fp.name, hash=fp.hash, description=fp.description)
            for name, fp in fps.items()
        }
        return cls(version=LOCKFILE_VERSION, server=server, tools=locked)

    def save(self, path: str | Path) -> Path:
        """Write the lockfile to disk as pretty JSON; returns the path written."""
        p = Path(path)
        p.write_text(self.model_dump_json(indent=2) + "\n", encoding="utf-8")
        return p

    @classmethod
    def load(cls, path: str | Path) -> LockFile:
        """Load and validate a lockfile from disk.

        Raises:
            FileNotFoundError: if the path does not exist.
            ValueError: if the file is not valid JSON or fails schema validation.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"lockfile not found: {p}")
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"lockfile is not valid JSON: {exc}") from exc
        return cls.model_validate(raw)


def default_lock_path(directory: str | Path = ".") -> Path:
    """Return the conventional lockfile path inside a directory."""
    return Path(directory) / LOCKFILE_NAME
