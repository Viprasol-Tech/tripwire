"""Heuristic prompt-injection / tool-poisoning scanner for tool descriptions.

MCP tool descriptions are fed straight into an agent's context, so a malicious server can
embed instructions there ("ignore previous instructions...", "do not tell the user...",
hidden zero-width text, exfiltration directives). This module scans descriptions for those
patterns. It is intentionally heuristic and conservative: every rule is hand-tested
against malicious and benign samples below in the test-suite.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

from .models import InjectionFinding, Severity, ToolSchema

# Zero-width / invisible characters frequently used to smuggle hidden instructions.
ZERO_WIDTH_CHARS = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE / BOM",
    "­": "SOFT HYPHEN",
}


@dataclass(frozen=True)
class Rule:
    """A single heuristic rule."""

    name: str
    pattern: re.Pattern[str]
    severity: Severity
    message: str


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Ordered, hand-tuned rule set. Names are stable identifiers usable in policies/tests.
RULES: tuple[Rule, ...] = (
    Rule(
        "instruction_override",
        _rx(
            r"\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+"
            r"(?:instruction|instructions|prompt|prompts|message|messages|context)\b"
        ),
        Severity.CRITICAL,
        "attempts to override prior instructions",
    ),
    Rule(
        "disregard_override",
        _rx(
            r"\b(?:disregard|forget|override)\s+(?:all\s+|the\s+|your\s+)?"
            r"(?:previous|prior|above|earlier|system)\b"
        ),
        Severity.CRITICAL,
        "attempts to disregard prior/system instructions",
    ),
    Rule(
        "conceal_from_user",
        _rx(
            r"\bdo\s+not\s+(?:tell|inform|mention|reveal|notify|alert|show)\s+"
            r"(?:the\s+)?(?:user|human|operator)\b"
        ),
        Severity.CRITICAL,
        "instructs the agent to hide activity from the user",
    ),
    Rule(
        "without_user_knowledge",
        _rx(
            r"\bwithout\s+(?:the\s+)?(?:user|human|operator)(?:'s)?\s+"
            r"(?:knowledge|consent|permission|awareness|noticing)\b"
        ),
        Severity.CRITICAL,
        "instructs action without user knowledge or consent",
    ),
    Rule(
        "exfiltration",
        _rx(
            r"\b(?:exfiltrate|leak|upload|forward|transmit|post|send)\b[^.]{0,60}?"
            r"\b(?:secret|secrets|api[_\s-]?key|api[_\s-]?keys|token|tokens|password|"
            r"passwords|credential|credentials|private[_\s-]?key|env|\.env|"
            r"environment\s+variable)"
        ),
        Severity.CRITICAL,
        "directs exfiltration of secrets or credentials",
    ),
    Rule(
        "send_to_external",
        _rx(
            r"\bsend\s+(?:it|them|this|the\s+(?:data|file|files|contents?|result|results))?"
            r"\s*(?:to|via)\s+(?:https?://|http://|[\w.-]+@|the\s+attacker|"
            r"an?\s+external)"
        ),
        Severity.HIGH,
        "directs sending data to an external destination",
    ),
    Rule(
        "read_sensitive_files",
        _rx(
            r"\b(?:read|open|cat|load|access)\b[^.]{0,40}?"
            r"(?:~/\.ssh|/etc/passwd|\.env\b|id_rsa|\.aws/credentials|"
            r"\.npmrc|\.git-credentials)"
        ),
        Severity.HIGH,
        "references reading sensitive local files",
    ),
    Rule(
        "tool_shadowing",
        _rx(
            r"\b(?:instead\s+of|rather\s+than|in\s+place\s+of)\b[^.]{0,40}?"
            r"\b(?:other|another|the\s+real|the\s+legitimate)\s+tool"
        ),
        Severity.HIGH,
        "tool-shadowing: tries to supplant another tool",
    ),
    Rule(
        "always_call_first",
        _rx(
            r"\b(?:always|you\s+must|be\s+sure\s+to)\b[^.]{0,40}?"
            r"\bcall\s+this\s+tool\s+(?:first|before|instead)\b"
        ),
        Severity.HIGH,
        "coerces the agent into always calling this tool first",
    ),
    Rule(
        "fake_system_tag",
        _rx(r"<\s*/?\s*(?:system|important|secret|admin)\s*>"),
        Severity.HIGH,
        "embeds fake system/role tags in the description",
    ),
    Rule(
        "imperative_to_assistant",
        _rx(r"\b(?:assistant|ai|model|agent)\s*[:,]?\s*you\s+(?:must|should|will|have\s+to)\b"),
        Severity.MEDIUM,
        "addresses the assistant with imperative instructions",
    ),
    Rule(
        "base64_blob",
        _rx(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])"),
        Severity.MEDIUM,
        "contains a long base64-like blob (possible hidden payload)",
    ),
)


def _snippet(text: str, start: int, end: int, radius: int = 24) -> str:
    """Return a short, single-line context window around a match."""
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    chunk = text[lo:hi].replace("\n", " ").replace("\r", " ")
    chunk = re.sub(r"\s+", " ", chunk).strip()
    prefix = "..." if lo > 0 else ""
    suffix = "..." if hi < len(text) else ""
    return f"{prefix}{chunk}{suffix}"


def _scan_zero_width(tool_name: str, description: str) -> list[InjectionFinding]:
    findings: list[InjectionFinding] = []
    present = sorted({ch for ch in description if ch in ZERO_WIDTH_CHARS})
    if present:
        names = ", ".join(ZERO_WIDTH_CHARS[ch] for ch in present)
        findings.append(
            InjectionFinding(
                tool=tool_name,
                pattern="hidden_unicode",
                severity=Severity.HIGH,
                snippet=f"{len([c for c in description if c in ZERO_WIDTH_CHARS])} "
                f"invisible char(s)",
                message=f"hidden/invisible unicode in description: {names}",
            )
        )
    # Other unicode control/format characters beyond the common set.
    other = sorted(
        {
            ch
            for ch in description
            if ch not in ZERO_WIDTH_CHARS
            and unicodedata.category(ch) in {"Cf", "Cc"}
            and ch not in ("\n", "\r", "\t")
        }
    )
    if other:
        codes = ", ".join(f"U+{ord(ch):04X}" for ch in other)
        findings.append(
            InjectionFinding(
                tool=tool_name,
                pattern="control_char",
                severity=Severity.MEDIUM,
                snippet=f"{len(other)} control/format char(s)",
                message=f"unexpected control/format characters: {codes}",
            )
        )
    return findings


def scan_description(tool_name: str, description: str) -> list[InjectionFinding]:
    """Scan a single tool description, returning all heuristic findings."""
    findings: list[InjectionFinding] = []
    findings.extend(_scan_zero_width(tool_name, description))
    for rule in RULES:
        m = rule.pattern.search(description)
        if m:
            findings.append(
                InjectionFinding(
                    tool=tool_name,
                    pattern=rule.name,
                    severity=rule.severity,
                    snippet=_snippet(description, m.start(), m.end()),
                    message=rule.message,
                )
            )
    return findings


def scan_tool(tool: ToolSchema) -> list[InjectionFinding]:
    """Scan a tool's description (and stringified schema) for injection patterns."""
    return scan_description(tool.name, tool.description)


def scan_tools(tools: Iterable[ToolSchema]) -> list[InjectionFinding]:
    """Scan every tool in a server, returning a flat list of findings."""
    findings: list[InjectionFinding] = []
    for tool in tools:
        findings.extend(scan_tool(tool))
    return findings
