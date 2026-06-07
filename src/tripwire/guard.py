"""TripWireGuard: enforce a policy against a pluggable tool provider.

The guard sits between your agent and an MCP server. It pulls the current tool schemas
from a :class:`ToolProvider`, evaluates them against the lockfile + policy, and raises
:class:`TripWireBlocked` if the server is poisoned or has drifted. The provider is an
interface so tests (and offline demos) can supply a fake without any network or MCP SDK.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .lockfile import LockFile
from .models import ToolSchema
from .policy import Decision, Policy, check


class TripWireBlocked(Exception):
    """Raised when the guard blocks use of a server."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(decision.reason)


@runtime_checkable
class ToolProvider(Protocol):
    """Anything that can return the current tool schemas of a server."""

    def list_tools(self) -> list[ToolSchema]: ...


class StaticToolProvider:
    """A trivial provider backed by an in-memory list (used in tests/demos)."""

    def __init__(self, tools: list[ToolSchema]) -> None:
        self._tools = list(tools)

    def list_tools(self) -> list[ToolSchema]:
        return list(self._tools)


class TripWireGuard:
    """Enforces a policy against a provider's current tools."""

    def __init__(
        self,
        provider: ToolProvider,
        lockfile: LockFile | None = None,
        policy: Policy | None = None,
    ) -> None:
        self.provider = provider
        self.lockfile = lockfile
        self.policy = policy or Policy()

    def evaluate(self) -> Decision:
        """Return the current Decision without raising."""
        return check(self.provider.list_tools(), self.lockfile, self.policy)

    def enforce(self) -> Decision:
        """Evaluate and raise :class:`TripWireBlocked` if the server is not allowed."""
        decision = self.evaluate()
        if not decision.allowed:
            raise TripWireBlocked(decision)
        return decision

    def approve_current(self, server: str = "default") -> LockFile:
        """Approve the provider's current state, updating and returning the lockfile."""
        self.lockfile = LockFile.from_tools(self.provider.list_tools(), server=server)
        return self.lockfile
