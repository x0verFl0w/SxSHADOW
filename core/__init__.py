"""
WRAITH core public API — all shared dataclasses live here so every module
imports from a single source of truth.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ExportEntry:
    """One entry from a PE export table."""
    name: str        # empty string when export is ordinal-only
    ordinal: int
    address: int     # RVA


@dataclass
class HijackCandidate:
    """A single (binary, hijackable_dll) pair that passed all filters."""
    binary_path: Path
    binary_arch: str                        # "x64" | "x86" | "unknown"
    binary_signed: Optional[bool]           # None = check failed / skipped
    binary_name: str                        # stem filename, e.g. "ngentask.exe"
    component_name: str                     # parsed from WinSxS folder
    component_version: str                  # e.g. "4.0.15805.0"

    hijackable_dll: str                     # lower-case dll name
    real_dll_path: Optional[Path]           # None if not found on disk
    real_dll_exports: List[ExportEntry] = field(default_factory=list)
    delay_loaded: bool = False

    score: int = 0
    score_breakdown: Dict[str, int] = field(default_factory=dict)

    # Suggested staging path for the operator
    suggested_drop_path: str = ""

    # ── Defensive / detection fields ─────────────────────────────────────────
    binary_sha256: Optional[str] = None         # SHA-256 of host binary
    real_dll_sha256: Optional[str] = None       # SHA-256 of resolved real DLL
    binary_publisher: Optional[str] = None      # Authenticode subject CN
    manifest_bound: bool = False                # import resolved via SxS manifest
    known_abused: bool = False                  # DLL appears in hijacklibs DB
    defensive_priority: int = 0                 # 0-100 detection-priority score
    defensive_breakdown: Dict[str, int] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Top-level object returned by scanner.scan()."""
    candidates: List[HijackCandidate]
    total_binaries_examined: int
    winsxs_path: Path
    scan_duration_seconds: float


__all__ = ["ExportEntry", "HijackCandidate", "ScanResult"]
