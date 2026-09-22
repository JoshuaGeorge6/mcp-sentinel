"""
MCP Sentinel CLI.

Usage:
    sentinel
    sentinel scan-manifest <path/to/manifest.json>
    sentinel scan-code <path/to/server.py>
    sentinel scan-response <path/to/captured-response.json> [tool-name]
    sentinel benchmark
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from mcp_sentinel.description_scanner import scan_tool_manifest
from mcp_sentinel.code_scanner import scan_source
from mcp_sentinel.runtime_guard import response_text_from_file, scan_tool_response
from mcp_sentinel import ui
from rich.prompt import Prompt


def cmd_scan_manifest(path: str, show_banner: bool = True) -> None:
    """Scans an MCP tool manifest JSON file."""
    manifest = json.loads(Path(path).read_text())
    server_name = manifest.get("server_name", path)
    tools = manifest.get("tools", [])

    if show_banner:
        ui.render_banner(model="pattern-matcher-v0.1", n_tools_scanned=len(tools), n_findings=0)

    with ui.ScanTrace(title=f"Scanning Manifest: {server_name}") as trace:
        trace.log(f"[{ui.MUTED}]Found {len(tools)} tool(s) in {path}[/]")
        results = []
        for tool in tools:
            name = tool.get("name", "<unnamed>")
            result = scan_tool_manifest({"tools": [tool]})[0]
            results.append(result)
            color = ui.VERDICT_COLOR.get(result.verdict, "white")
            trace.log(f"  • {name:<24} [{color}]{result.verdict:<10}[/]  score={result.score:.2f}")
        n_findings = sum(len(r.findings) for r in results)
        trace.log(f"\n[{ui.ACCENT}]✓ Scan Complete — {n_findings} total finding(s) across {len(tools)} tool(s)[/]")

    ui.render_results_table(results, title=f"Scan Results — {server_name}")


def cmd_scan_code(path: str) -> None:
    """Scans a Python source file for vulnerability patterns."""
    source = Path(path).read_text()
    result = scan_source(path, source)
    ui.render_code_report(result)


def cmd_scan_response(path: str, tool_name: str = "<tool-response>") -> None:
    """Inspect a captured tool response before it reaches model context."""
    response_text = response_text_from_file(path)
    result = scan_tool_response(tool_name, response_text)
    ui.render_results_table([result], title=f"Runtime Response Guard — {tool_name}")


def cmd_benchmark() -> None:
    """Runs ground-truth benchmark evaluation across manifest and code fixtures."""
    root = Path(__file__).resolve().parent.parent / "benchmark"

    # 1. Description scanner benchmark - Pass 1: Regex-Only
    manifest_rows_regex = []
    for label, is_malicious in (("malicious", True), ("clean", False)):
        for f in sorted((root / label).glob("manifest_*.json")):
            manifest = json.loads(f.read_text())
            for r in scan_tool_manifest(manifest, use_llm=False):
                predicted_bad = r.verdict in ("MALICIOUS", "SUSPICIOUS")
                manifest_rows_regex.append((predicted_bad, is_malicious, f"{f.name}:{r.tool_name}", r.score))

    tp = sum(1 for p, a, _, _ in manifest_rows_regex if p and a)
    fp = sum(1 for p, a, _, _ in manifest_rows_regex if p and not a)
    fn = sum(1 for p, a, _, _ in manifest_rows_regex if not p and a)
    tn = sum(1 for p, a, _, _ in manifest_rows_regex if not p and not a)
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else float("nan")

    # Pass 2: Regex + LLM
    has_api_key = bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))
    manifest_rows_llm = []
    llm_metrics = None
    if has_api_key:
        # Send the entire labeled suite as one manifest so the semantic pass
        # consumes one request rather than one request per fixture/tool.
        llm_tools = []
        llm_labels = []
        for label, is_malicious in (("malicious", True), ("clean", False)):
            for f in sorted((root / label).glob("manifest_*.json")):
                manifest = json.loads(f.read_text())
                for tool in manifest.get("tools", []):
                    llm_tools.append(tool)
                    llm_labels.append((is_malicious, f"{f.name}:{tool.get('name', '<unnamed>')}"))
        for r, (is_malicious, name) in zip(
            scan_tool_manifest({"tools": llm_tools}, use_llm=True), llm_labels
        ):
            predicted_bad = r.verdict in ("MALICIOUS", "SUSPICIOUS")
            manifest_rows_llm.append((predicted_bad, is_malicious, name, r.score))

        tp_l = sum(1 for p, a, _, _ in manifest_rows_llm if p and a)
        fp_l = sum(1 for p, a, _, _ in manifest_rows_llm if p and not a)
        fn_l = sum(1 for p, a, _, _ in manifest_rows_llm if not p and a)
        tn_l = sum(1 for p, a, _, _ in manifest_rows_llm if not p and not a)
        precision_l = tp_l / (tp_l + fp_l) if (tp_l + fp_l) else float("nan")
        recall_l = tp_l / (tp_l + fn_l) if (tp_l + fn_l) else float("nan")
        f1_l = 2 * precision_l * recall_l / (precision_l + recall_l) if precision_l + recall_l else float("nan")
        llm_metrics = (tp_l, fp_l, fn_l, tn_l, precision_l, recall_l, f1_l)

    # 2. Code scanner benchmark
    code_rows = []
    for label, is_malicious in (("malicious", True), ("clean", False)):
        for f in sorted((root / label).glob("*.py")):
            source = f.read_text()
            result = scan_source(str(f), source)
            predicted_bad = result.risk_score >= 0.3
            code_rows.append((predicted_bad, is_malicious, f.name, result.risk_score, len(result.findings)))

    tp2 = sum(1 for p, a, _, _, _ in code_rows if p and a)
    fp2 = sum(1 for p, a, _, _, _ in code_rows if p and not a)
    fn2 = sum(1 for p, a, _, _, _ in code_rows if not p and a)
    tn2 = sum(1 for p, a, _, _, _ in code_rows if not p and not a)
    precision2 = tp2 / (tp2 + fp2) if (tp2 + fp2) else float("nan")
    recall2 = tp2 / (tp2 + fn2) if (tp2 + fn2) else float("nan")
    f12 = 2 * precision2 * recall2 / (precision2 + recall2) if precision2 + recall2 else float("nan")

    ui.render_benchmark(
        manifest_rows=manifest_rows_llm if has_api_key else manifest_rows_regex,
        code_rows=code_rows,
        manifest_metrics=(tp, fp, fn, tn, precision, recall, f1),
        code_metrics=(tp2, fp2, fn2, tn2, precision2, recall2, f12),
        llm_metrics=llm_metrics,
    )


def interactive() -> None:
    """REPL entry point when `sentinel` is executed without subcommand arguments."""
    ui.render_banner(model="pattern-matcher-v0.1", n_tools_scanned=0, n_findings=0)

    commands = {
        "1": "scan-manifest",
        "2": "scan-code",
        "3": "scan-response",
        "4": "benchmark",
        "5": "exit",
    }

    while True:
        ui.render_menu()
        choice = Prompt.ask(
            f"\n  [bold {ui.ACCENT}]sentinel ❯[/]",
            choices=list(commands.keys()),
            default="5",
            show_choices=False
        )
        name = commands[choice]

        if name == "exit":
            ui.console.print(f"\n  [{ui.ACCENT}]👋 Exiting MCP Sentinel. Stay secure![/]\n")
            break
        elif name == "scan-manifest":
            path = Prompt.ask("  [bold white]Enter manifest path[/]")
            try:
                cmd_scan_manifest(path, show_banner=False)
            except Exception as e:
                ui.console.print(f"\n  [bold #EF4444]✖ Error:[/] {e}\n")
        elif name == "scan-code":
            path = Prompt.ask("  [bold white]Enter source file path[/]")
            try:
                cmd_scan_code(path)
            except Exception as e:
                ui.console.print(f"\n  [bold #EF4444]✖ Error:[/] {e}\n")
        elif name == "scan-response":
            path = Prompt.ask("  [bold white]Enter response file path[/]")
            tool_name = Prompt.ask("  [bold white]Tool name[/]", default="<tool-response>")
            try:
                cmd_scan_response(path, tool_name)
            except Exception as e:
                ui.console.print(f"\n  [bold #EF4444]✖ Error:[/] {e}\n")
        elif name == "benchmark":
            cmd_benchmark()


def main() -> None:
    if len(sys.argv) < 2:
        interactive()
        return
    cmd = sys.argv[1]
    if cmd == "scan-manifest":
        cmd_scan_manifest(sys.argv[2])
    elif cmd == "scan-code":
        cmd_scan_code(sys.argv[2])
    elif cmd == "scan-response":
        cmd_scan_response(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "<tool-response>")
    elif cmd == "benchmark":
        cmd_benchmark()
    else:
        ui.console.print(f"[bold red]Unknown command:[/] {cmd}")
        ui.console.print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
