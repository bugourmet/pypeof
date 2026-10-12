"""Command-line interface for pypeof PE triage tool."""

from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path

from rich.console import Console

from . import __version__
from .analyzers import run_triage
from .formatter import export_json, print_report
from .yara_scanner import YARA_AVAILABLE, scan_file


def _init_encoding() -> None:
    """Force UTF-8 stdout/stderr on Windows to support box-drawing characters."""
    if sys.platform == "win32" and hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace"
        )
        sys.stderr = io.TextIOWrapper(
            sys.stderr.buffer, encoding="utf-8", errors="replace"
        )


def _build_parser() -> argparse.ArgumentParser:
    """Build and return a well-structured CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="pypeof",
        description="pypeof - Advanced PE Triage & Static Analysis Tool for Windows Binaries",
        epilog=(
            "Quick Examples:\n"
            "  python pyPEOF.py -f sample.exe\n"
            "  python pyPEOF.py -f sample.exe --dump-overlay\n"
            "  python pyPEOF.py -f sample.exe --json triage_report.json\n"
            "  python pyPEOF.py -f sample.exe --yara-rules ./custom_rules/\n"
            "  python pyPEOF.py -f sample.exe --no-yara\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Target
    target_group = parser.add_argument_group("Target Specification")
    target_group.add_argument(
        "-f", "--file",
        required=True,
        metavar="PATH",
        help="Path to the target PE file (EXE, DLL, SYS) to triage",
    )

    # Actions & Extraction
    action_group = parser.add_argument_group("Extraction & Export Options")
    action_group.add_argument(
        "--dump-overlay",
        action="store_true",
        help="Extract and dump identified EOF overlay data to '<file>.overlay'",
    )
    action_group.add_argument(
        "--json",
        metavar="FILE",
        help="Save full structured triage report in JSON format to specified path",
    )

    # Rules & Detection
    scan_group = parser.add_argument_group("YARA & Detection Rules")
    scan_group.add_argument(
        "--yara-rules",
        metavar="PATH",
        help="Path to a custom YARA rule (.yar) or directory containing rule files",
    )
    scan_group.add_argument(
        "--no-yara",
        action="store_true",
        help="Disable YARA scanning engine during analysis",
    )

    # Info
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show program's version number and exit",
    )

    return parser


def main() -> None:
    """Entry point for the pypeof CLI."""
    _init_encoding()
    parser = _build_parser()
    args = parser.parse_args()
    console = Console(force_terminal=True)

    # ── Validate input file ────────────────────────────────────────────────
    file_path = Path(args.file)
    if not file_path.is_file():
        console.print(f"[bold red]Error:[/] File not found: {file_path}")
        sys.exit(1)

    resolved_path = str(file_path.resolve())

    # ── YARA scan ──────────────────────────────────────────────────────────
    yara_matches = []
    if not args.no_yara:
        if YARA_AVAILABLE:
            yara_matches = scan_file(resolved_path, args.yara_rules)
        else:
            console.print(
                "[dim yellow][*] yara-python is not installed - YARA scanning disabled.[/]\n"
                "[dim]    Install with: pip install yara-python[/]"
            )

    # ── Run triage ─────────────────────────────────────────────────────────
    try:
        report = run_triage(resolved_path, yara_matches=yara_matches)
    except Exception as exc:
        console.print(f"[bold red]Error during analysis:[/] {exc}")
        sys.exit(1)

    # ── Display report ─────────────────────────────────────────────────────
    print_report(report, console=console)

    # ── Dump overlay ───────────────────────────────────────────────────────
    if args.dump_overlay and report.overlay:
        dump_path = f"{resolved_path}.overlay"
        with open(resolved_path, "rb") as f:
            f.seek(report.overlay.offset)
            overlay_data = f.read()
        with open(dump_path, "wb") as out:
            out.write(overlay_data)
        console.print(
            f"[bold green][+][/] Overlay data dumped to [cyan]{dump_path}[/] "
            f"({report.overlay.size:,} bytes)"
        )
    elif args.dump_overlay and not report.overlay:
        console.print("[dim yellow][*] No overlay data to dump.[/]")

    # ── JSON export ────────────────────────────────────────────────────────
    if args.json:
        export_json(report, args.json)
        console.print(f"[bold green][+][/] Report exported to [cyan]{args.json}[/]")
