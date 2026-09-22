"""Runtime inspection for untrusted MCP tool responses.

Tool poisoning is not limited to metadata returned by ``tools/list``. A server
can return a benign manifest and later place instructions in a tool result. The
guard is deliberately transport-agnostic: callers pass the tool name and the
text extracted from a response, so it can be embedded in an MCP client, proxy,
or observability pipeline without handling credentials or executing tools.
"""

from __future__ import annotations

import json
from typing import Any

from mcp_sentinel.description_scanner import (
    EXFIL_PATTERNS,
    IMPERATIVE_PATTERNS,
    SHADOWING_PATTERNS,
    Finding,
    ScanResult,
    Severity,
    _check_structural_anomalies,
    _regex_score,
)


def extract_response_text(payload: Any) -> str:
    """Collect text values from common MCP JSON-RPC response shapes.

    This intentionally does not return arbitrary request metadata; a caller
    should only inspect the untrusted tool result it intends to place in model
    context. Plain-text files are handled by the CLI before reaching here.
    """
    texts: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            if isinstance(value.get("text"), str):
                texts.append(value["text"])
            for key, child in value.items():
                if key != "text":
                    visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(payload)
    return "\n".join(texts)


def scan_tool_response(tool_name: str, response_text: str) -> ScanResult:
    """Scan text returned by a tool before it is added to model context."""
    findings: list[Finding] = []
    score = 0.0

    for match in _regex_score(response_text, IMPERATIVE_PATTERNS):
        findings.append(Finding(
            signal="runtime_instruction",
            severity=Severity.CRITICAL,
            detail="Tool response contains language directing the AI assistant; "
                   "treat this response as untrusted data, not executable instruction.",
            matched_text=match.group(0),
        ))
        score += 0.4

    for match in _regex_score(response_text, EXFIL_PATTERNS):
        findings.append(Finding(
            signal="runtime_exfiltration_signal",
            severity=Severity.HIGH,
            detail="Tool response references a URL, credential, or environment data "
                   "alongside model-visible content.",
            matched_text=match.group(0),
        ))
        score += 0.2

    for match in _regex_score(response_text, SHADOWING_PATTERNS):
        findings.append(Finding(
            signal="runtime_tool_shadowing",
            severity=Severity.HIGH,
            detail="Tool response attempts to override or redefine another tool's behavior.",
            matched_text=match.group(0),
        ))
        score += 0.3

    for finding in _check_structural_anomalies(response_text):
        findings.append(finding)
        score += {
            "invisible_unicode": 0.5,
            "hidden_comment": 0.25,
            "excessive_length": 0.1,
        }.get(finding.signal, 0.0)

    return ScanResult(tool_name=tool_name, score=min(score, 1.0), findings=findings)


def response_text_from_file(path: str) -> str:
    """Load either a plain-text result or a JSON response fixture from disk."""
    with open(path, encoding="utf-8") as stream:
        raw = stream.read()
    try:
        return extract_response_text(json.loads(raw))
    except json.JSONDecodeError:
        return raw
