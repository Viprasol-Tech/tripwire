# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-06-07

### Added
- Deterministic tool-schema fingerprinting (canonical JSON -> SHA-256).
- `.tripwire-lock.json` lockfile: save/load, schema validation, "approve current state".
- Drift detection: new / removed / description-changed / schema-changed tools with
  severity; post-approval description change (the rug-pull) flagged HIGH.
- Heuristic injection scanner: instruction override, conceal-from-user, exfiltration,
  send-to-external, sensitive-file reads, tool-shadowing, fake system tags, base64 blobs,
  and hidden/zero-width unicode detection.
- Policy engine (`strict` / `permissive` presets + tunable thresholds) and a single
  `check()` decision function.
- `TripWireGuard` over a pluggable `ToolProvider`, raising `TripWireBlocked` on violations.
- Optional `tripwire.mcp_wrap` adapter for a live MCP `ClientSession` (lazy import).
- Typer CLI: `scan`, `approve`, `demo`, `version`. Fully offline demo.
- 69 unit tests; `mypy --strict` clean; `ruff` clean; `py.typed` shipped.

[0.1.0]: https://github.com/Viprasol-Tech/tripwire/releases/tag/v0.1.0
