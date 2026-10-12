"""Core analysis engines for PE triage."""

from __future__ import annotations

import datetime
import hashlib
import math
import os
from typing import Optional

import pefile

from .models import (
    SectionInfo, OverlayInfo, TimestampInfo, YaraMatch, TriageReport
)

# --------------------------------------------------------------------------- #
#  Hashing helpers
# --------------------------------------------------------------------------- #

def compute_file_hashes(file_path: str) -> tuple[str, str, str]:
    """Return (md5, sha1, sha256) hex digests for a file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def compute_bytes_hash(data: bytes, algo: str = "md5") -> str:
    """Return hex digest of raw bytes."""
    h = hashlib.new(algo)
    h.update(data)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
#  Entropy calculation
# --------------------------------------------------------------------------- #

def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence (0.0 – 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


# --------------------------------------------------------------------------- #
#  Section analysis
# --------------------------------------------------------------------------- #

# Common section characteristics flags
_SECTION_FLAGS = {
    0x00000020: "CNT_CODE",
    0x00000040: "CNT_INITIALIZED_DATA",
    0x00000080: "CNT_UNINITIALIZED_DATA",
    0x20000000: "MEM_EXECUTE",
    0x40000000: "MEM_READ",
    0x80000000: "MEM_WRITE",
}


def _decode_characteristics(value: int) -> str:
    """Decode section characteristics into human-readable flags."""
    flags = [name for bit, name in _SECTION_FLAGS.items() if value & bit]
    return " | ".join(flags) if flags else f"0x{value:08X}"


def _detect_section_anomalies(section: pefile.SectionStructure, entropy: float) -> list[str]:
    """Identify suspicious traits in a PE section."""
    anomalies: list[str] = []
    name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
    chars = section.Characteristics

    # High entropy – likely packed/encrypted
    if entropy > 7.0:
        anomalies.append(f"Very high entropy ({entropy:.2f}) – possibly packed or encrypted")
    elif entropy > 6.5:
        anomalies.append(f"Elevated entropy ({entropy:.2f}) – could indicate compression")

    # Writable + executable (RWX)
    if (chars & 0x80000000) and (chars & 0x20000000):
        anomalies.append("Section is WRITE + EXECUTE (RWX) – common in packers")

    # Executable code section with no code flag
    if (chars & 0x20000000) and not (chars & 0x00000020):
        anomalies.append("Executable section missing CNT_CODE flag")

    # Zero raw size but non-zero virtual size (potential hollowing)
    if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
        anomalies.append("Raw size is 0 but virtual size is non-zero – possible section hollowing")

    # Virtual size significantly larger than raw size
    if section.SizeOfRawData > 0:
        ratio = section.Misc_VirtualSize / section.SizeOfRawData
        if ratio > 10:
            anomalies.append(f"Virtual/raw size ratio is {ratio:.1f}x – suspicious inflation")

    # Non-standard section name
    standard_names = {".text", ".rdata", ".data", ".rsrc", ".reloc", ".pdata", ".edata", ".idata", ".tls", ".bss", ".CRT", ".debug"}
    if name and name not in standard_names and not name.startswith("."):
        anomalies.append(f"Non-standard section name '{name}'")

    # Zero entropy on initialized data section (possible padding / anti-analysis)
    if entropy == 0.0 and section.SizeOfRawData > 512:
        anomalies.append("Zero entropy on large section – null-padded or anti-analysis")

    return anomalies


def analyze_sections(pe: pefile.PE) -> list[SectionInfo]:
    """Analyze all PE sections: entropy, hashes, anomalies."""
    results: list[SectionInfo] = []
    for section in pe.sections:
        data = section.get_data()
        entropy = shannon_entropy(data)
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        info = SectionInfo(
            name=name,
            virtual_address=section.VirtualAddress,
            virtual_size=section.Misc_VirtualSize,
            raw_size=section.SizeOfRawData,
            entropy=entropy,
            md5=compute_bytes_hash(data, "md5"),
            characteristics=_decode_characteristics(section.Characteristics),
            anomalies=_detect_section_anomalies(section, entropy),
        )
        results.append(info)
    return results


# --------------------------------------------------------------------------- #
#  Overlay / EOF analysis
# --------------------------------------------------------------------------- #

def analyze_overlay(pe: pefile.PE, file_path: str) -> Optional[OverlayInfo]:
    """Detect and analyze data appended after the PE end-of-file marker."""
    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset is None:
        return None

    with open(file_path, "rb") as f:
        f.seek(overlay_offset)
        overlay_data = f.read()

    if not overlay_data:
        return None

    preview_len = min(128, len(overlay_data))
    preview_bytes = overlay_data[:preview_len]

    return OverlayInfo(
        offset=overlay_offset,
        size=len(overlay_data),
        entropy=shannon_entropy(overlay_data),
        md5=compute_bytes_hash(overlay_data, "md5"),
        sha256=compute_bytes_hash(overlay_data, "sha256"),
        preview_hex=preview_bytes.hex(" "),
        preview_ascii="".join(
            chr(b) if 32 <= b < 127 else "." for b in preview_bytes
        ),
    )


# --------------------------------------------------------------------------- #
#  Timestamp analysis
# --------------------------------------------------------------------------- #

def analyze_timestamp(pe: pefile.PE) -> TimestampInfo:
    """Inspect the PE compile timestamp for suspicious values."""
    raw = pe.FILE_HEADER.TimeDateStamp
    suspicious = False
    reason = "Timestamp appears normal"

    try:
        dt = datetime.datetime.fromtimestamp(raw, tz=datetime.timezone.utc)
    except (OSError, OverflowError, ValueError):
        return TimestampInfo(
            raw_value=raw,
            datetime_utc=None,
            suspicious=True,
            reason="Timestamp value is out of valid range",
        )

    now = datetime.datetime.now(tz=datetime.timezone.utc)

    # Future timestamp
    if dt > now:
        suspicious = True
        reason = f"Timestamp is in the future ({dt.isoformat()})"

    # Before Windows NT era (1993)
    elif dt.year < 1993:
        suspicious = True
        reason = f"Timestamp predates Windows NT ({dt.year})"

    # Null / epoch
    elif raw == 0:
        suspicious = True
        reason = "Timestamp is zeroed out (epoch) – likely tampered"

    # Delphi / Borland magic timestamp
    elif raw == 0x2A425E19:
        suspicious = True
        reason = "Borland/Delphi magic timestamp (0x2A425E19)"

    return TimestampInfo(
        raw_value=raw,
        datetime_utc=dt,
        suspicious=suspicious,
        reason=reason,
    )


# --------------------------------------------------------------------------- #
#  Import hash
# --------------------------------------------------------------------------- #

def compute_imphash(pe: pefile.PE) -> Optional[str]:
    """Compute the import hash (imphash) of the PE."""
    try:
        return pe.get_imphash()
    except Exception:
        return None


# --------------------------------------------------------------------------- #
#  Risk indicators
# --------------------------------------------------------------------------- #

def assess_risk(report: TriageReport) -> list[str]:
    """Aggregate risk indicators from all analysis results."""
    indicators: list[str] = []

    if report.compile_timestamp.suspicious:
        indicators.append(f"[!] Suspicious timestamp: {report.compile_timestamp.reason}")

    if report.overlay:
        indicators.append(f"[!] Overlay data detected: {report.overlay.size:,} bytes at offset 0x{report.overlay.offset:X}")
        if report.overlay.entropy > 7.0:
            indicators.append("[!] Overlay has very high entropy - possibly encrypted payload")

    for sec in report.sections:
        for anomaly in sec.anomalies:
            indicators.append(f"[!] Section [{sec.name}]: {anomaly}")

    if report.yara_matches:
        for match in report.yara_matches:
            indicators.append(f"[CRITICAL] YARA hit: {match.rule_name} - {match.description}")

    return indicators


# --------------------------------------------------------------------------- #
#  Full triage pipeline
# --------------------------------------------------------------------------- #

def run_triage(file_path: str, yara_matches: Optional[list[YaraMatch]] = None) -> TriageReport:
    """Execute the full PE triage analysis pipeline."""
    pe = pefile.PE(file_path)
    md5, sha1, sha256 = compute_file_hashes(file_path)

    machine = pe.FILE_HEADER.Machine
    if machine == 0x14C:
        arch = "x86 (32-bit)"
    elif machine == 0x8664:
        arch = "x64 (64-bit)"
    elif machine == 0xAA64:
        arch = "ARM64"
    else:
        arch = f"Unknown (0x{machine:X})"

    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    is_exe = bool(pe.FILE_HEADER.Characteristics & 0x0002) and not is_dll
    is_driver = bool(
        pe.FILE_HEADER.Characteristics & 0x2000
        and hasattr(pe, "DIRECTORY_ENTRY_EXPORT")
    )  # rough heuristic

    report = TriageReport(
        file_path=file_path,
        file_size=os.path.getsize(file_path),
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        imphash=compute_imphash(pe),
        architecture=arch,
        is_dll=is_dll,
        is_exe=is_exe,
        is_driver=is_driver,
        entry_point=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        compile_timestamp=analyze_timestamp(pe),
        sections=analyze_sections(pe),
        overlay=analyze_overlay(pe, file_path),
        yara_matches=yara_matches or [],
    )

    report.risk_indicators = assess_risk(report)
    pe.close()
    return report
