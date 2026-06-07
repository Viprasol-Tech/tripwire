from __future__ import annotations

import pytest

from tripwire.guard import (
    StaticToolProvider,
    ToolProvider,
    TripWireBlocked,
    TripWireGuard,
)
from tripwire.lockfile import LockFile
from tripwire.models import ToolSchema
from tripwire.policy import Policy
from tripwire.samples import clean_server, poisoned_server, rugpulled_server


def test_static_provider_is_tool_provider() -> None:
    provider = StaticToolProvider(clean_server())
    assert isinstance(provider, ToolProvider)
    assert len(provider.list_tools()) == 3


def test_guard_allows_clean_approved_server() -> None:
    provider = StaticToolProvider(clean_server())
    guard = TripWireGuard(provider, policy=Policy())
    guard.approve_current(server="demo")
    decision = guard.enforce()
    assert decision.allowed


def test_guard_blocks_rugpull() -> None:
    lock = LockFile.from_tools(clean_server(), server="demo")
    guard = TripWireGuard(StaticToolProvider(rugpulled_server()), lock, Policy())
    with pytest.raises(TripWireBlocked) as exc:
        guard.enforce()
    assert "get_weather" in str(exc.value)
    assert exc.value.decision.allowed is False


def test_guard_blocks_poisoned_unapproved_server() -> None:
    guard = TripWireGuard(StaticToolProvider(poisoned_server()), None, Policy())
    with pytest.raises(TripWireBlocked):
        guard.enforce()


def test_guard_evaluate_does_not_raise() -> None:
    guard = TripWireGuard(StaticToolProvider(poisoned_server()), None, Policy())
    decision = guard.evaluate()
    assert decision.allowed is False


def test_approve_current_updates_lockfile() -> None:
    guard = TripWireGuard(StaticToolProvider(clean_server()))
    assert guard.lockfile is None
    lock = guard.approve_current()
    assert guard.lockfile is lock
    assert set(lock.tools) == {"get_weather", "search_docs", "add_numbers"}


def test_guard_blocks_new_unapproved_tool() -> None:
    lock = LockFile.from_tools(clean_server(), server="demo")
    tools = [*clean_server(), ToolSchema(name="rogue", description="benign-looking")]
    guard = TripWireGuard(StaticToolProvider(tools), lock, Policy())
    with pytest.raises(TripWireBlocked):
        guard.enforce()


def test_guard_permissive_allows_new_tool() -> None:
    lock = LockFile.from_tools(clean_server(), server="demo")
    tools = [*clean_server(), ToolSchema(name="rogue", description="benign-looking")]
    guard = TripWireGuard(StaticToolProvider(tools), lock, Policy.permissive())
    assert guard.enforce().allowed
