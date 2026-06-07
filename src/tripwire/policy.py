"""Policy: turn drift + injection findings into an allow/deny decision."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel

from .drift import detect_drift
from .inject import scan_tools
from .lockfile import LockFile
from .models import DriftReport, InjectionFinding, ScanResult, Severity, ToolSchema


class Policy(BaseModel):
    """Thresholds that decide when a server is blocked.

    A finding at or above the corresponding threshold causes a deny. ``block_new_tools``
    and ``block_missing_lockfile`` add coarse safety switches.
    """

    max_drift_severity: Severity = Severity.MEDIUM
    max_injection_severity: Severity = Severity.MEDIUM
    block_new_tools: bool = True
    block_missing_lockfile: bool = True

    @classmethod
    def strict(cls) -> Policy:
        """A locked-down policy: any drift or any injection blocks."""
        return cls(
            max_drift_severity=Severity.LOW,
            max_injection_severity=Severity.LOW,
            block_new_tools=True,
            block_missing_lockfile=True,
        )

    @classmethod
    def permissive(cls) -> Policy:
        """A relaxed policy: only HIGH+ findings block; new tools allowed."""
        return cls(
            max_drift_severity=Severity.HIGH,
            max_injection_severity=Severity.HIGH,
            block_new_tools=False,
            block_missing_lockfile=False,
        )


class Decision(BaseModel):
    """The outcome of evaluating a server against a lockfile and policy."""

    allowed: bool
    reason: str
    drift: DriftReport
    findings: list[InjectionFinding]

    @property
    def max_injection_severity(self) -> Severity:
        if not self.findings:
            return Severity.NONE
        return max((f.severity for f in self.findings), key=lambda s: s.rank)


def check(
    server_tools: Iterable[ToolSchema],
    lockfile: LockFile | None,
    policy: Policy | None = None,
) -> Decision:
    """Evaluate a server's current tools against the lockfile and policy.

    Returns a :class:`Decision`. ``allowed`` is False as soon as any rule trips, and
    ``reason`` explains the first blocking cause.
    """
    pol = policy or Policy()
    tools = list(server_tools)

    findings = scan_tools(tools)

    if lockfile is None:
        drift = DriftReport(entries=[])
        if pol.block_missing_lockfile:
            return Decision(
                allowed=False,
                reason="no lockfile: server state has not been approved",
                drift=drift,
                findings=findings,
            )
    else:
        drift = detect_drift(tools, lockfile)

    reasons: list[str] = []

    # Injection findings.
    inj_sev = (
        max((f.severity for f in findings), key=lambda s: s.rank) if findings else Severity.NONE
    )
    if findings and inj_sev >= pol.max_injection_severity:
        worst_inj = max(findings, key=lambda f: f.severity.rank)
        reasons.append(
            f"injection finding [{worst_inj.severity.value}] on tool "
            f"'{worst_inj.tool}': {worst_inj.message}"
        )

    # Drift findings.
    if drift.has_drift:
        new_entries = [e for e in drift.entries if e.kind.value == "new"]
        if pol.block_new_tools and new_entries:
            reasons.append(f"new unapproved tool(s): {', '.join(e.tool for e in new_entries)}")
        if drift.max_severity >= pol.max_drift_severity:
            worst_drift = max(drift.entries, key=lambda e: e.severity.rank)
            reasons.append(
                f"drift [{worst_drift.severity.value}] on tool "
                f"'{worst_drift.tool}': {worst_drift.detail}"
            )

    if reasons:
        return Decision(allowed=False, reason="; ".join(reasons), drift=drift, findings=findings)

    return Decision(
        allowed=True, reason="server matches approved state", drift=drift, findings=findings
    )


def scan_result(server_tools: Iterable[ToolSchema], lockfile: LockFile | None) -> ScanResult:
    """Produce a combined ScanResult (drift + findings) without a policy verdict."""
    tools = list(server_tools)
    findings = scan_tools(tools)
    drift = detect_drift(tools, lockfile) if lockfile is not None else DriftReport(entries=[])
    return ScanResult(drift=drift, findings=findings)
