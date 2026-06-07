"""Core data models for tripwire.

These are pure pydantic models with no MCP or network dependencies, so they can be
imported and tested in any environment.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Ordered severity levels used across drift and injection findings."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank for comparisons (higher is more severe)."""
        order = {
            Severity.NONE: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self]

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


class ToolSchema(BaseModel):
    """A single MCP tool definition as advertised by a server."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)


class ToolFingerprint(BaseModel):
    """A deterministic fingerprint of one tool's schema."""

    name: str
    hash: str
    description: str = ""


class DriftKind(str, Enum):
    """The kind of change observed for a tool relative to the lockfile."""

    NEW = "new"
    REMOVED = "removed"
    DESCRIPTION_CHANGED = "description_changed"
    SCHEMA_CHANGED = "schema_changed"


class DriftEntry(BaseModel):
    """A single drift observation for one tool."""

    tool: str
    kind: DriftKind
    severity: Severity
    detail: str = ""
    old_hash: str | None = None
    new_hash: str | None = None


class DriftReport(BaseModel):
    """The full result of comparing a server's current state to the lockfile."""

    entries: list[DriftEntry] = Field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return len(self.entries) > 0

    @property
    def max_severity(self) -> Severity:
        if not self.entries:
            return Severity.NONE
        return max((e.severity for e in self.entries), key=lambda s: s.rank)

    def of_kind(self, kind: DriftKind) -> list[DriftEntry]:
        return [e for e in self.entries if e.kind == kind]


class InjectionFinding(BaseModel):
    """A single heuristic prompt-injection / poisoning match in a tool description."""

    tool: str
    pattern: str
    severity: Severity
    snippet: str
    message: str


class ScanResult(BaseModel):
    """Combined drift + injection result for a server scan."""

    drift: DriftReport
    findings: list[InjectionFinding] = Field(default_factory=list)

    @property
    def max_injection_severity(self) -> Severity:
        if not self.findings:
            return Severity.NONE
        return max((f.severity for f in self.findings), key=lambda s: s.rank)
