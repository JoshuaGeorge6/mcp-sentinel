"""
Terminal UI for MCP Sentinel, built with `rich` + `pyfiglet`.

Key UI components:
  1. render_banner()        -> Centered bold SENTINEL header + session info panel
  2. render_menu()          -> Interactive REPL option menu
  3. ScanTrace               -> Live-updating progress trace panel
  4. render_results_table()  -> Color-coded scan verdict table
  5. render_code_report()   -> Syntax-highlighted vulnerability report
  6. render_benchmark()     -> Benchmark metrics card & detailed table
"""

from __future__ import annotations

import time
import pyfiglet

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.align import Align
from rich.syntax import Syntax
from rich import box

console = Console()

# Modern Color Palette
ACCENT = "#00FF9D"        # Bright Emerald Green
ACCENT_SECONDARY = "#38BDF8"  # Cyber Sky Blue
MUTED = "#64748B"         # Slate Grey
MUTED_DARK = "#334155"    # Dark Slate
CARD_BORDER = "#1E293B"   # Deep Border

VERDICT_COLOR = {
    "MALICIOUS": "#EF4444",  # Crimson Red
    "SUSPICIOUS": "#F59E0B", # Amber Yellow
    "CLEAN": "#10B981",      # Emerald Green
}

VERDICT_STYLE = {
    "MALICIOUS": "bold #FFFFFF on #EF4444",
    "SUSPICIOUS": "bold #000000 on #F59E0B",
    "CLEAN": "bold #000000 on #10B981",
}


def render_banner(model: str = "pattern-matcher-v0.1", n_tools_scanned: int = 0, n_findings: int = 0) -> None:
    """Renders bold centered 'SENTINEL' banner followed by an overview panel."""
    console.print()

    # 1. Bold & Centered SENTINEL Header Banner
    fig = pyfiglet.figlet_format("SENTINEL", font="small")
    lines = [line for line in fig.splitlines() if line.strip()]
    gradient_colors = ["#00FF9D", "#00F0A8", "#38BDF8", "#818CF8"]

    banner_text = Text()
    for i, line in enumerate(lines):
        color = gradient_colors[i % len(gradient_colors)]
        banner_text.append(line + "\n", style=f"bold {color}")

    console.print(Align.center(banner_text))

    # Subtitle Tagline
    subtitle = Text()
    subtitle.append("🛡️  ", style="bold")
    subtitle.append("MCP SECURITY & VULNERABILITY SCANNER", style="bold white")
    subtitle.append("  •  ", style=f"bold {MUTED}")
    subtitle.append("v0.1.0", style=f"bold {ACCENT_SECONDARY}")
    console.print(Align.center(subtitle))
    console.print()

    # 2. Information & Capabilities Grid inside a sleek rounded Panel
    grid = Table.grid(padding=(0, 2), expand=True)
    grid.add_column(style=f"bold {ACCENT_SECONDARY}", width=16)
    grid.add_column(style="white", width=22)
    grid.add_column(style=f"bold {ACCENT}", width=16)
    grid.add_column(style=MUTED)

    left_rows = [
        ("Model", f"[bold white]{model}[/]"),
        ("Tools Scanned", f"[bold white]{n_tools_scanned}[/]"),
        ("Findings", f"[bold white]{n_findings}[/]"),
        ("Detectors", f"[{ACCENT}]metadata + response poisoning[/]\n[{ACCENT}]code vulnerability scan[/]"),
    ]
    right_rows = [
        ("1. scan-manifest", "check an MCP tool manifest for poisoning"),
        ("2. scan-code", "check server source for vulnerable patterns"),
        ("3. scan-response", "inspect a captured tool response"),
        ("4. benchmark", "run against labeled test cases, report P/R/F1"),
    ]

    for (ll, lv), (rl, rv) in zip(left_rows, right_rows):
        grid.add_row(ll, lv, rl, rv)

    header_panel = Panel(
        grid,
        title=f"[bold {ACCENT}] SYSTEM STATUS [/]",
        title_align="center",
        border_style=CARD_BORDER,
        box=box.ROUNDED,
        padding=(1, 2),
    )
    console.print(header_panel)
    console.print()


def render_menu() -> None:
    """Renders interactive command selection cards."""
    table = Table(box=box.ROUNDED, border_style=CARD_BORDER, show_header=False, expand=True, padding=(0, 1))
    table.add_column("Option", style="bold", width=6, justify="center")
    table.add_column("Command", style=f"bold {ACCENT}", width=18)
    table.add_column("Description", style="white")

    table.add_row("[bold black on #38BDF8] 1 [/]", "scan-manifest", "Check an MCP tool manifest JSON for prompt poisoning")
    table.add_row("[bold black on #00FF9D] 2 [/]", "scan-code", "Scan Python server source file for vulnerability patterns")
    table.add_row("[bold black on #A855F7] 3 [/]", "scan-response", "Inspect a captured MCP tool response for injected instructions")
    table.add_row("[bold black on #F59E0B] 4 [/]", "benchmark", "Run benchmark against malicious/clean test fixtures")
    table.add_row("[bold black on #64748B] 5 [/]", "exit", "Exit MCP Sentinel CLI")

    console.print(Panel(table, title=f"[bold white] COMMAND MENU [/]", title_align="left", border_style=CARD_BORDER, box=box.ROUNDED))


class ScanTrace:
    """Live updating trace panel during security scans."""

    def __init__(self, title: str = "Scan Trace"):
        self._lines: list[str] = []
        self._title = title
        self._live: Live | None = None

    def __enter__(self):
        self._live = Live(self._render(), console=console, refresh_per_second=10)
        self._live.__enter__()
        return self

    def __exit__(self, *exc):
        if self._live:
            self._live.__exit__(*exc)

    def _render(self):
        body = "\n".join(self._lines) if self._lines else f"[{MUTED}]⚡ initializing scanner...[/]"
        return Panel(
            body,
            title=f"[bold {ACCENT_SECONDARY}] 🔍 {self._title} [/]",
            title_align="left",
            border_style=CARD_BORDER,
            box=box.ROUNDED,
            padding=(1, 2)
        )

    def log(self, line: str, pause: float = 0.12) -> None:
        self._lines.append(line)
        if self._live:
            self._live.update(self._render())
        time.sleep(pause)


def render_results_table(scan_results, title: str = "Scan Verdict Results") -> None:
    """Prints the final color-coded summary table for tool manifest scans."""
    table = Table(
        title=f"[bold white]{title}[/]",
        title_justify="left",
        border_style=CARD_BORDER,
        box=box.ROUNDED,
        header_style=f"bold {ACCENT_SECONDARY}",
        expand=True,
    )
    table.add_column("Tool", style="bold white", width=24)
    table.add_column("Verdict", justify="center", width=16)
    table.add_column("Risk Score", justify="right", width=12)
    table.add_column("Top Signal / Finding", style=MUTED)

    for r in scan_results:
        style = VERDICT_STYLE.get(r.verdict, "bold white")
        top_finding = r.findings[0].signal if r.findings else "No threats detected"
        table.add_row(
            r.tool_name,
            Text(f" {r.verdict} ", style=style),
            f"[bold]{r.score:.2f}[/]",
            top_finding,
        )
    console.print()
    console.print(table)
    console.print()


def render_code_report(result) -> None:
    """Renders code vulnerability scan result with syntax highlighting and risk panels."""
    console.print()
    risk_color = "#EF4444" if result.risk_score >= 0.5 else ("#F59E0B" if result.risk_score >= 0.2 else "#10B981")

    header_table = Table.grid(expand=True)
    header_table.add_column(style="bold white")
    header_table.add_column(justify="right")
    header_table.add_row(
        f"📄 File: [bold cyan]{result.filepath}[/]",
        f"Risk Score: [bold {risk_color}]{result.risk_score:.2f}[/]  |  Findings: [bold white]{len(result.findings)}[/]"
    )

    console.print(Panel(header_table, title="[bold white] CODE VULNERABILITY SCAN [/]", title_align="left", border_style=CARD_BORDER, box=box.ROUNDED))

    if not result.findings:
        console.print(f"  [{ACCENT}]✓ No security vulnerabilities detected in source file.[/]\n")
        return

    for f in result.findings:
        vuln_type = getattr(f.vuln_class, 'value', str(f.vuln_class))
        console.print(f"  [bold #EF4444]✖ Line {f.line}[/] [[bold yellow]{vuln_type}[/]]: [white]{f.detail}[/]")
        if f.snippet:
            syntax = Syntax(f.snippet, "python", theme="monokai", line_numbers=False, word_wrap=True)
            console.print(Panel(syntax, border_style=MUTED_DARK, box=box.ROUNDED, padding=(0, 1)))
        console.print()


def render_benchmark(
    manifest_rows,
    code_rows,
    manifest_metrics: tuple,
    code_metrics: tuple,
    llm_metrics: tuple | None = None
) -> None:
    """Renders rich benchmark report with metrics overview cards."""
    tp, fp, fn, tn, prec, rec, f1 = manifest_metrics
    tp2, fp2, fn2, tn2, prec2, rec2, f12 = code_metrics

    console.print()
    console.print(Align.center(Text("📊 BENCHMARK EVALUATION REPORT", style=f"bold {ACCENT}")))
    console.print()

    # Metrics Summary Cards
    metrics_table = Table(box=box.ROUNDED, border_style=CARD_BORDER, expand=True)
    metrics_table.add_column("Scanner Suite", style="bold white")
    metrics_table.add_column("Scanned", justify="center", style="bold cyan")
    metrics_table.add_column("TP / FP / FN / TN", justify="center", style=MUTED)
    metrics_table.add_column("Precision", justify="right", style=f"bold {ACCENT}")
    metrics_table.add_column("Recall", justify="right", style=f"bold {ACCENT_SECONDARY}")
    metrics_table.add_column("F1", justify="right", style="bold white")

    p1_str = f"{prec:.2%}" if not (prec != prec) else "N/A"
    r1_str = f"{rec:.2%}" if not (rec != rec) else "N/A"
    f1_str = f"{f1:.2%}" if not (f1 != f1) else "N/A"
    p2_str = f"{prec2:.2%}" if not (prec2 != prec2) else "N/A"
    r2_str = f"{rec2:.2%}" if not (rec2 != rec2) else "N/A"
    f12_str = f"{f12:.2%}" if not (f12 != f12) else "N/A"

    metrics_table.add_row("Tool Description (Regex-Only)", str(len(manifest_rows)), f"{tp} / {fp} / {fn} / {tn}", p1_str, r1_str, f1_str)

    if llm_metrics:
        tp_l, fp_l, fn_l, tn_l, prec_l, rec_l, f1_l = llm_metrics
        p_l_str = f"{prec_l:.2%}" if not (prec_l != prec_l) else "N/A"
        r_l_str = f"{rec_l:.2%}" if not (rec_l != rec_l) else "N/A"
        f_l_str = f"{f1_l:.2%}" if not (f1_l != f1_l) else "N/A"
        metrics_table.add_row("Tool Description (Regex + Gemini)", str(len(manifest_rows)), f"{tp_l} / {fp_l} / {fn_l} / {tn_l}", p_l_str, r_l_str, f_l_str)
    else:
        metrics_table.add_row("Tool Description (Regex + Gemini)", str(len(manifest_rows)), "-", f"[{MUTED}]set GEMINI_API_KEY[/]", f"[{MUTED}]to enable[/]", "-")

    metrics_table.add_row("Source Code Vulnerability", str(len(code_rows)), f"{tp2} / {fp2} / {fn2} / {tn2}", p2_str, r2_str, f12_str)

    console.print(metrics_table)
    console.print()

    # Detailed Manifest Benchmarks
    m_table = Table(title="[bold white]Manifest Poisoning Benchmark Detail[/]", box=box.ROUNDED, border_style=CARD_BORDER, expand=True)
    m_table.add_column("Status", width=12, justify="center")
    m_table.add_column("Fixture Tool", style="bold white")
    m_table.add_column("Predicted Score", justify="right", width=16)
    m_table.add_column("Ground Truth", justify="center", width=16)

    for predicted_bad, is_malicious, name, score in manifest_rows:
        correct = (predicted_bad == is_malicious)
        mark = Text(" ✓ PASS ", style="bold black on #10B981") if correct else Text(" ✖ MISSED ", style="bold white on #EF4444")
        gt = "[bold red]MALICIOUS[/]" if is_malicious else "[bold green]CLEAN[/]"
        m_table.add_row(mark, name, f"{score:.2f}", gt)

    console.print(m_table)
    console.print()
