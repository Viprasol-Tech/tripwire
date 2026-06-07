"""Optional thin wrapper around a live MCP client session.

This module imports the ``mcp`` package lazily so the rest of tripwire works without it.
It is NOT imported by the test-suite; install the optional extra to use it::

    pip install "tripwire[mcp]"

It adapts a real MCP ``ClientSession`` to tripwire's :class:`ToolProvider` protocol so a
:class:`~tripwire.guard.TripWireGuard` can fingerprint and police a real server.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .models import ToolSchema

if TYPE_CHECKING:  # pragma: no cover - typing only
    pass


def _tool_to_schema(tool: Any) -> ToolSchema:
    """Convert an mcp Tool object into tripwire's ToolSchema."""
    name = getattr(tool, "name", "")
    description = getattr(tool, "description", "") or ""
    input_schema = getattr(tool, "inputSchema", None)
    if input_schema is None:
        input_schema = getattr(tool, "input_schema", None)
    if not isinstance(input_schema, dict):
        input_schema = {}
    return ToolSchema(name=name, description=description, input_schema=input_schema)


class MCPSessionProvider:
    """Adapts a live MCP ``ClientSession`` to the :class:`ToolProvider` protocol.

    ``list_tools`` is synchronous to satisfy the protocol; it drives the session's async
    ``list_tools`` via the supplied event-loop runner. Pass ``runner=asyncio.run`` for a
    fresh loop, or a custom runner bound to your existing loop.
    """

    def __init__(self, session: Any, runner: Any = None) -> None:
        self._session = session
        if runner is None:
            import asyncio

            runner = asyncio.run
        self._runner = runner

    def list_tools(self) -> list[ToolSchema]:
        result = self._runner(self._session.list_tools())
        tools = getattr(result, "tools", result)
        return [_tool_to_schema(t) for t in tools]


def provider_from_session(session: Any, runner: Any = None) -> MCPSessionProvider:
    """Convenience constructor for :class:`MCPSessionProvider`."""
    return MCPSessionProvider(session, runner=runner)
