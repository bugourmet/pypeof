"""YARA rule scanning engine for PE triage."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from .models import YaraMatch

# YARA is optional – degrade gracefully if not installed
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

_RULES_DIR = Path(__file__).parent / "rules"


def _compile_rules(custom_rules_path: Optional[str] = None) -> "yara.Rules | None":
    """Compile all .yar/.yara files from the built-in rules directory
    and optionally from a user-supplied path."""
    if not YARA_AVAILABLE:
        return None

    rule_files: dict[str, str] = {}
    
    # Built-in rules
    if _RULES_DIR.is_dir():
        for rule_file in sorted(_RULES_DIR.glob("*.yar")):
            namespace = rule_file.stem
            rule_files[namespace] = str(rule_file)

    # Custom user rules
    if custom_rules_path:
        custom_path = Path(custom_rules_path)
        if custom_path.is_file():
            rule_files[custom_path.stem] = str(custom_path)
        elif custom_path.is_dir():
            for rule_file in sorted(custom_path.glob("*.yar")):
                rule_files[f"custom_{rule_file.stem}"] = str(rule_file)

    if not rule_files:
        return None

    return yara.compile(filepaths=rule_files)


def scan_file(file_path: str, custom_rules_path: Optional[str] = None) -> list[YaraMatch]:
    """Scan a PE file against all available YARA rules.
    
    Returns a list of YaraMatch objects for each rule that triggered.
    Returns an empty list if YARA is not installed.
    """
    if not YARA_AVAILABLE:
        return []

    rules = _compile_rules(custom_rules_path)
    if rules is None:
        return []

    matches = rules.match(file_path)
    results: list[YaraMatch] = []

    for match in matches:
        description = match.meta.get("description", "No description")
        tags = list(match.tags) if match.tags else []
        matched_strings = []
        for string_match in match.strings:
            for instance in string_match.instances:
                matched_strings.append(
                    f"0x{instance.offset:X}: {string_match.identifier} => {instance.matched_data[:64]}"
                )
        results.append(
            YaraMatch(
                rule_name=match.rule,
                tags=tags,
                description=description,
                matched_strings=matched_strings,
            )
        )

    return results
