"""Rich terminal formatter for PE triage reports."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

from rich.align import Align
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from .models import TriageReport


# ─── Helpers ───────────────────────────────────────────────────────────────── #

def format_size(size_bytes: int) -> str:
    """Convert bytes to human-readable format (e.g., KB, MB)."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / (1024 ** 2):.2f} MB"
    else:
        return f"{size_bytes / (1024 ** 3):.2f} GB"


def entropy_color(entropy: float) -> str:
    """Return rich color name based on entropy value."""
    if entropy < 4.0:
        return "green"
    elif entropy <= 6.5:
        return "yellow"
    return "red"


def entropy_bar(entropy: float, width: int = 20) -> str:
    """Generate a visual entropy bar using rich markup."""
    normalized = min(max(entropy, 0.0), 8.0)
    filled = int((normalized / 8.0) * width)
    empty = width - filled
    color = entropy_color(entropy)
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim]"


_BANNER = r"""
 ██████╗ ██╗   ██╗██████╗ ███████╗ ██████╗ ███████╗
 ██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██╔═══██╗██╔════╝
 ██████╔╝ ╚████╔╝ ██████╔╝█████╗  ██║   ██║█████╗
 ██╔═══╝   ╚██╔╝  ██╔═══╝ ██╔══╝  ██║   ██║██╔══╝
 ██║        ██║   ██║     ███████╗╚██████╔╝██║
 ╚═╝        ╚═╝   ╚═╝     ╚══════╝ ╚═════╝ ╚═╝
"""


# ─── JSON Export ───────────────────────────────────────────────────────────── #

class _ReportEncoder(json.JSONEncoder):
    """Serialise dataclasses and datetimes to JSON."""

    def default(self, obj: Any) -> Any:
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return dataclasses.asdict(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def export_json(report: TriageReport, output_path: str) -> None:
    """Write the triage report as pretty-printed JSON."""
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, cls=_ReportEncoder, indent=2)


# ─── Report Renderer ──────────────────────────────────────────────────────── #

def print_report(report: TriageReport, console: Optional[Console] = None) -> None:
    """Render a complete triage report to the terminal."""
    con = console or Console(force_terminal=True)
    con.print()

    # ── Banner ─────────────────────────────────────────────────────────────
    banner = Panel(
        Align.center(Text(_BANNER, style="bold cyan")),
        subtitle="[bold blue]PE Triage Tool v2.0.0[/]",
        border_style="cyan",
        expand=False,
    )
    con.print(Align.center(banner))

    # ── File Identity ──────────────────────────────────────────────────────
    identity = Text()
    identity.append("  File Path  ", style="bold")
    identity.append(f"{report.file_path}\n")
    identity.append("  Size       ", style="bold")
    identity.append(f"{report.file_size:,} bytes ({format_size(report.file_size)})\n")
    identity.append("  MD5        ", style="bold")
    identity.append(f"{report.md5}\n", style="magenta")
    identity.append("  SHA-1      ", style="bold")
    identity.append(f"{report.sha1}\n", style="magenta")
    identity.append("  SHA-256    ", style="bold")
    identity.append(f"{report.sha256}\n", style="magenta")
    if report.imphash:
        identity.append("  Imphash    ", style="bold")
        identity.append(f"{report.imphash}", style="cyan")

    con.print(Panel(identity, title="[bold white] File Identity ", border_style="blue"))

    # ── PE Header ──────────────────────────────────────────────────────────
    pe_type = "Executable (EXE)" if report.is_exe else (
        "Dynamic Link Library (DLL)" if report.is_dll else (
            "Kernel Driver (SYS)" if report.is_driver else "Unknown"
        )
    )

    header = Text()
    header.append("  Architecture  ", style="bold")
    header.append(f"{report.architecture}\n")
    header.append("  Type          ", style="bold")
    header.append(f"{pe_type}\n")
    header.append("  Entry Point   ", style="bold")
    header.append(f"0x{report.entry_point:08X}\n")
    header.append("  Compile Time  ", style="bold")

    ts = report.compile_timestamp
    if ts.datetime_utc:
        header.append(f"{ts.datetime_utc.strftime('%Y-%m-%d %H:%M:%S UTC')} ")
    else:
        header.append("Invalid/Unknown ")
    header.append(f"(0x{ts.raw_value:08X}) ")
    if ts.suspicious:
        header.append(f"  [!] {ts.reason}", style="bold red")

    con.print(Panel(header, title="[bold white] PE Header ", border_style="blue"))

    # ── Section Table ──────────────────────────────────────────────────────
    sec_table = Table(
        title="Section Analysis",
        title_style="bold white",
        border_style="blue",
        expand=True,
        show_lines=True,
    )
    sec_table.add_column("Name", style="cyan", no_wrap=True, width=12)
    sec_table.add_column("VirtAddr", style="dim", justify="right", width=12)
    sec_table.add_column("VirtSize", justify="right", width=10)
    sec_table.add_column("RawSize", justify="right", width=10)
    sec_table.add_column("Entropy", width=28)
    sec_table.add_column("MD5", style="dim magenta", width=34)
    sec_table.add_column("Characteristics", ratio=1)

    section_anomalies: list[str] = []

    for sec in report.sections:
        color = entropy_color(sec.entropy)
        ent_display = f"[{color}]{sec.entropy:.4f}[/{color}]  {entropy_bar(sec.entropy, 12)}"

        sec_table.add_row(
            sec.name,
            f"0x{sec.virtual_address:08X}",
            format_size(sec.virtual_size),
            format_size(sec.raw_size),
            ent_display,
            sec.md5,
            sec.characteristics,
        )

        for anomaly in sec.anomalies:
            section_anomalies.append(
                f"  [bold red][!][/]  [bold]{escape(sec.name)}[/]: {escape(anomaly)}"
            )

    con.print(sec_table)
    if section_anomalies:
        con.print()
        for line in section_anomalies:
            con.print(line)
    con.print()

    # ── Overlay ────────────────────────────────────────────────────────────
    if report.overlay:
        ov = report.overlay
        ov_color = entropy_color(ov.entropy)

        # Build overlay body as markup string for proper rendering
        ov_lines = [
            f"  [bold]Offset[/]   0x{ov.offset:X}",
            f"  [bold]Size[/]     {ov.size:,} bytes ({format_size(ov.size)})",
            f"  [bold]Entropy[/]  [{ov_color}]{ov.entropy:.4f}[/{ov_color}]  {entropy_bar(ov.entropy, 15)}",
            f"  [bold]MD5[/]      [magenta]{ov.md5}[/]",
            f"  [bold]SHA-256[/]  [magenta]{ov.sha256}[/]",
            "",
            "  [bold]Hex Preview:[/]",
            f"  [dim]{escape(ov.preview_hex)}[/]",
            "",
            "  [bold]ASCII Preview:[/]",
            f"  [dim]{escape(ov.preview_ascii)}[/]",
        ]

        con.print(Panel(
            "\n".join(ov_lines),
            title="[bold white] Overlay / EOF Data ",
            border_style="yellow",
        ))
        con.print()

    # ── YARA Matches ───────────────────────────────────────────────────────
    if report.yara_matches:
        for match in report.yara_matches:
            # Determine severity color from meta (stored in description for now)
            sev_color = "blue"
            desc_lower = match.description.lower()
            if any(t.lower() in ("high",) for t in match.tags):
                sev_color = "red"
            elif any(t.lower() in ("medium",) for t in match.tags):
                sev_color = "yellow"

            lines = [f"  [italic dim]{escape(match.description)}[/]"]
            if match.matched_strings:
                lines.append("")
                lines.append("  [bold]Matched Strings:[/]")
                for s in match.matched_strings[:10]:  # cap display
                    lines.append(f"    [red]>[/] {escape(str(s))}")
                if len(match.matched_strings) > 10:
                    lines.append(f"    [dim]... and {len(match.matched_strings) - 10} more[/]")

            con.print(Panel(
                "\n".join(lines),
                title=f"[bold {sev_color}] YARA: {escape(match.rule_name)} ",
                border_style=sev_color,
            ))
        con.print()

    # ── Risk Assessment ────────────────────────────────────────────────────
    if report.risk_indicators:
        risk_lines = [f"  {escape(r)}" for r in report.risk_indicators]
        con.print(Panel(
            "\n".join(risk_lines),
            title="[bold white] Risk Assessment ",
            border_style="red",
        ))
    else:
        con.print(Panel(
            "  [bold green][+] No significant risks detected.[/]",
            title="[bold white] Risk Assessment ",
            border_style="green",
        ))
    con.print()

    # ── Verdict ────────────────────────────────────────────────────────────
    if report.yara_matches:
        verdict = "[bold red]█ MALICIOUS INDICATORS DETECTED █[/]"
        border = "red"
    elif report.risk_indicators:
        verdict = "[bold yellow]█ SUSPICIOUS █[/]"
        border = "yellow"
    else:
        verdict = "[bold green]█ CLEAN █[/]"
        border = "green"

    con.print(Panel(
        Align.center(verdict),
        border_style=border,
        padding=(1, 4),
    ))
    con.print()
