"""MCP server adapter for MCP Sentinel's deterministic security scanners.

The server accepts content from the connected MCP client and returns structured
security findings. It intentionally does not expose arbitrary local file reads
or tool execution: the client is responsible for supplying the manifest, source
code, or tool response it wants reviewed.
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from mcp_sentinel.code_scanner import scan_source
from mcp_sentinel.description_scanner import scan_tool_manifest
from mcp_sentinel.runtime_guard import extract_response_text, scan_tool_response


MAX_INPUT_CHARS = 200_000


def _require_bounded_text(value: str, field_name: str) -> None:
    if len(value) > MAX_INPUT_CHARS:
        raise ValueError(f"{field_name} exceeds the {MAX_INPUT_CHARS:,}-character safety limit")


def _finding_dict(finding: Any) -> dict[str, str]:
    return {
        "signal": getattr(finding, "signal", getattr(finding, "vuln_class", "unknown")).value
        if hasattr(getattr(finding, "signal", getattr(finding, "vuln_class", "unknown")), "value")
        else str(getattr(finding, "signal", getattr(finding, "vuln_class", "unknown"))),
        "severity": getattr(getattr(finding, "severity", None), "value", "high"),
        "detail": finding.detail,
        "evidence": getattr(finding, "matched_text", "") or getattr(finding, "snippet", ""),
        "line": str(getattr(finding, "line", "")),
    }


def _manifest_result(manifest: dict[str, Any], enable_semantic_llm: bool = False) -> dict[str, Any]:
    """Run the metadata scanner and return client-enforceable JSON."""
    if not isinstance(manifest.get("tools", []), list):
        raise ValueError("manifest.tools must be a list")
    serialized = str(manifest)
    _require_bounded_text(serialized, "manifest")
    results = scan_tool_manifest(manifest, use_llm=enable_semantic_llm)
    return {
        "scanner": "mcp-sentinel",
        "scan_type": "tool_manifest",
        "should_block": any(result.verdict == "MALICIOUS" for result in results),
        "results": [
            {
                "tool_name": result.tool_name,
                "verdict": result.verdict,
                "score": result.score,
                "findings": [_finding_dict(finding) for finding in result.findings],
            }
            for result in results
        ],
        "enforcement_note": "Apply should_block in deterministic client policy; do not delegate enforcement to an LLM.",
    }


def _source_result(source: str, filename: str = "server.py") -> dict[str, Any]:
    """Run source analysis on client-supplied Python only."""
    _require_bounded_text(source, "source")
    result = scan_source(filename, source)
    return {
        "scanner": "mcp-sentinel",
        "scan_type": "python_source",
        "risk_score": result.risk_score,
        "should_block": result.risk_score >= 0.7,
        "findings": [_finding_dict(finding) for finding in result.findings],
        "enforcement_note": "A finding is a review signal. Block only according to your organization’s policy.",
    }


def _response_result(tool_name: str, response: str | dict[str, Any]) -> dict[str, Any]:
    """Inspect a client-supplied tool response before it reaches model context."""
    response_text = response if isinstance(response, str) else extract_response_text(response)
    _require_bounded_text(response_text, "response")
    result = scan_tool_response(tool_name, response_text)
    return {
        "scanner": "mcp-sentinel",
        "scan_type": "tool_response",
        "tool_name": tool_name,
        "verdict": result.verdict,
        "score": result.score,
        "should_block": result.verdict == "MALICIOUS",
        "findings": [_finding_dict(finding) for finding in result.findings],
        "enforcement_note": "Do not add blocked response text to the model context.",
    }


server = MCPServer(
    name="mcp-sentinel",
    title="MCP Sentinel",
    version="0.1.0",
    description="Deterministic security scans for MCP manifests, Python server code, and tool responses.",
    instructions=(
        "Use these tools to analyze untrusted MCP content. Treat scanner output as evidence. "
        "The connected client, not the model, must enforce should_block."
    ),
)


@server.tool(
    name="scan_tool_manifest",
    description="Scan an MCP tools/list manifest for tool poisoning and return structured findings.",
    structured_output=True,
)
def scan_tool_manifest_tool(
    manifest: dict[str, Any], enable_semantic_llm: bool = False
) -> dict[str, Any]:
    """Scan client-provided MCP tool metadata. LLM analysis is off by default."""
    return _manifest_result(manifest, enable_semantic_llm)


@server.tool(
    name="scan_python_source",
    description="Statically scan client-provided Python MCP server source for risky patterns.",
    structured_output=True,
)
def scan_python_source_tool(source: str, filename: str = "server.py") -> dict[str, Any]:
    """Scan supplied source; never reads an arbitrary path on the host."""
    return _source_result(source, filename)


@server.tool(
    name="scan_tool_response",
    description="Inspect a captured MCP tool response for injected instructions before model-context insertion.",
    structured_output=True,
)
def scan_tool_response_tool(tool_name: str, response: str | dict[str, Any]) -> dict[str, Any]:
    """Scan text or a JSON-RPC result object supplied by the client."""
    return _response_result(tool_name, response)


@server.tool(
    name="get_security_policy",
    description="Return Sentinel's deterministic enforcement guidance and current safety limits.",
    structured_output=True,
)
def get_security_policy() -> dict[str, Any]:
    return {
        "enforcement": {
            "manifest": "Block when any tool verdict is MALICIOUS.",
            "tool_response": "Block when response verdict is MALICIOUS.",
            "source_code": "Review findings; the default should_block threshold is risk_score >= 0.7.",
        },
        "input_limit_chars": MAX_INPUT_CHARS,
        "semantic_llm_default": False,
        "privacy": "This MCP server only analyzes content passed by the client and does not expose arbitrary host file reads.",
        "limitation": "Static and heuristic findings require human review; an LLM does not make enforcement decisions.",
    }


def main() -> None:
    """Run MCP Sentinel over stdio for MCP-compatible desktop and agent clients."""
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
