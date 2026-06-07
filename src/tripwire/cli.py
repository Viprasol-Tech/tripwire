"""tripwire command-line interface."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .drift import detect_drift
from .guard import StaticToolProvider, TripWireBlocked, TripWireGuard
from .inject import scan_tools
from .lockfile import LockFile, default_lock_path
from .models import DriftReport, InjectionFinding, Severity, ToolSchema
from .policy import Policy
from .samples import clean_server, poisoned_server, rugpulled_server

app = typer.Typer(
    name="tripwire",
    help="Runtime guard against MCP tool-poisoning and silent tool drift.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

_SEV_STYLE = {
    Severity.NONE: "green",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}


def _sev(sev: Severity) -> str:
    return f"[{_SEV_STYLE[sev]}]{sev.value.upper()}[/]"


def _drift_table(report: DriftReport) -> Table:
    table = Table(title="Tool drift vs lockfile", title_style="bold", expand=False)
    table.add_column("Tool", style="bold")
    table.add_column("Change")
    table.add_column("Severity")
    table.add_column("Detail")
    if not report.entries:
        table.add_row("-", "none", _sev(Severity.NONE), "no drift detected")
        return table
    for e in report.entries:
        table.add_row(e.tool, e.kind.value, _sev(e.severity), e.detail)
    return table


def _injection_table(findings: list[InjectionFinding]) -> Table:
    table = Table(title="Injection / poisoning findings", title_style="bold", expand=False)
    table.add_column("Tool", style="bold")
    table.add_column("Pattern")
    table.add_column("Severity")
    table.add_column("Message")
    if not findings:
        table.add_row("-", "none", _sev(Severity.NONE), "no injection patterns found")
        return table
    for f in findings:
        table.add_row(f.tool, f.pattern, _sev(f.severity), f.message)
    return table


def _load_lock_optional(path: str) -> LockFile | None:
    try:
        return LockFile.load(path)
    except FileNotFoundError:
        return None


@app.command()
def version() -> None:
    """Print the tripwire version."""
    console.print(f"tripwire {__version__}")


@app.command()
def scan(
    lock: str = typer.Option(
        str(default_lock_path()), "--lock", "-l", help="Path to the lockfile."
    ),
    sample: str = typer.Option(
        "rugpull",
        "--sample",
        "-s",
        help="Built-in sample server to scan: clean | rugpull | poisoned.",
    ),
) -> None:
    """Scan a (sample) MCP server for drift and injection, printing rich tables."""
    servers = {
        "clean": clean_server,
        "rugpull": rugpulled_server,
        "poisoned": poisoned_server,
    }
    if sample not in servers:
        console.print(f"[red]unknown sample '{sample}'. choose: {', '.join(servers)}[/]")
        raise typer.Exit(code=2)
    tools: list[ToolSchema] = servers[sample]()

    lockfile = _load_lock_optional(lock)
    drift = detect_drift(tools, lockfile) if lockfile else DriftReport(entries=[])
    findings = scan_tools(tools)

    console.print(_drift_table(drift))
    console.print(_injection_table(findings))

    guard = TripWireGuard(StaticToolProvider(tools), lockfile, Policy())
    decision = guard.evaluate()
    if decision.allowed:
        console.print(Panel(f"ALLOWED - {escape(decision.reason)}", style="green"))
    else:
        console.print(Panel(f"BLOCKED - {escape(decision.reason)}", style="bold red"))
        raise typer.Exit(code=1)


@app.command()
def approve(
    lock: str = typer.Option(
        str(default_lock_path()), "--lock", "-l", help="Path to write the lockfile."
    ),
    sample: str = typer.Option(
        "clean", "--sample", "-s", help="Sample server to approve: clean | rugpull | poisoned."
    ),
) -> None:
    """Approve the current state of a (sample) server, writing the lockfile."""
    servers = {
        "clean": clean_server,
        "rugpull": rugpulled_server,
        "poisoned": poisoned_server,
    }
    if sample not in servers:
        console.print(f"[red]unknown sample '{sample}'. choose: {', '.join(servers)}[/]")
        raise typer.Exit(code=2)
    tools = servers[sample]()
    lockfile = LockFile.from_tools(tools, server=sample)
    written = lockfile.save(lock)
    console.print(
        Panel(
            f"Approved {len(lockfile.tools)} tool(s) from '{sample}' server.\n"
            f"Lockfile written to {written}",
            title="tripwire approve",
            style="green",
        )
    )


@app.command()
def demo() -> None:
    """Offline end-to-end demo: approve a clean server, then catch a rug-pull + poison."""
    console.print(
        Panel(
            "tripwire demo - offline, no network, no API keys.\n"
            "1) Approve a clean MCP server (pin its tool fingerprints).\n"
            "2) Reconnect to a RUG-PULLED server (a tool's description changed).\n"
            "3) Connect to a freshly POISONED server (hidden injection in a tool).",
            title="tripwire",
            style="bold cyan",
        )
    )

    # Step 1: approve the clean server.
    clean = clean_server()
    guard = TripWireGuard(StaticToolProvider(clean), policy=Policy())
    lockfile = guard.approve_current(server="demo")
    console.print(
        f"\n[green][1] Approved[/] {len(lockfile.tools)} clean tools: {', '.join(lockfile.tools)}"
    )
    decision = guard.enforce()
    console.print(f"    re-check of clean server -> [green]ALLOWED[/] ({decision.reason})")

    # Step 2: the same server rug-pulls get_weather.
    console.print("\n[bold][2] Server reconnects after a RUG-PULL[/]")
    rug = rugpulled_server()
    rug_guard = TripWireGuard(StaticToolProvider(rug), lockfile, Policy())
    drift = detect_drift(rug, lockfile)
    findings = scan_tools(rug)
    console.print(_drift_table(drift))
    console.print(_injection_table(findings))
    try:
        rug_guard.enforce()
        console.print("[red]    ERROR: rug-pull was NOT blocked![/]")
    except TripWireBlocked as exc:
        console.print(Panel(f"BLOCKED rug-pull - {escape(exc.decision.reason)}", style="bold red"))

    # Step 3: a brand-new poisoned server (no approval).
    console.print("\n[bold][3] New POISONED server (never approved)[/]")
    poison = poisoned_server()
    poison_guard = TripWireGuard(StaticToolProvider(poison), None, Policy())
    p_findings = scan_tools(poison)
    console.print(_injection_table(p_findings))
    try:
        poison_guard.enforce()
        console.print("[red]    ERROR: poisoned server was NOT blocked![/]")
    except TripWireBlocked as exc:
        console.print(Panel(f"BLOCKED poison - {escape(exc.decision.reason)}", style="bold red"))

    console.print(
        Panel(
            "Result: tripwire blocked BOTH the rug-pull and the poisoned server, offline.\n"
            "One import stands between your agent and a hijacked MCP server.",
            title="done",
            style="bold green",
        )
    )


if __name__ == "__main__":
    app()
