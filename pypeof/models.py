from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
import datetime

@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    md5: str
    characteristics: str
    anomalies: list[str] = field(default_factory=list)

@dataclass
class OverlayInfo:
    offset: int
    size: int
    entropy: float
    md5: str
    sha256: str
    preview_hex: str
    preview_ascii: str

@dataclass
class TimestampInfo:
    raw_value: int
    datetime_utc: Optional[datetime.datetime]
    suspicious: bool
    reason: str

@dataclass
class YaraMatch:
    rule_name: str
    tags: list[str]
    description: str
    matched_strings: list[str]

@dataclass
class TriageReport:
    file_path: str
    file_size: int
    md5: str
    sha1: str
    sha256: str
    imphash: Optional[str]
    architecture: str
    is_dll: bool
    is_exe: bool
    is_driver: bool
    entry_point: int
    compile_timestamp: TimestampInfo
    sections: list[SectionInfo] = field(default_factory=list)
    overlay: Optional[OverlayInfo] = None
    yara_matches: list[YaraMatch] = field(default_factory=list)
    risk_indicators: list[str] = field(default_factory=list)
