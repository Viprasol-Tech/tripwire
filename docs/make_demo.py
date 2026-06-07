"""Render the real `tripwire demo` output to docs/assets/demo.svg.

This imports the repo's own CLI demo logic and points its module-level
``console`` at a recording :class:`rich.console.Console`, so the rendered
image matches the actual command output exactly. Run with::

    PYTHONPATH=src python docs/make_demo.py
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from tripwire import cli

OUT = Path(__file__).resolve().parent / "assets" / "demo.svg"


def main() -> None:
    recorder = Console(record=True, width=100)
    # Point the CLI's module-level console at the recorder so demo() draws here.
    cli.console = recorder
    cli.demo()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    recorder.save_svg(str(OUT), title="tripwire demo")
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
