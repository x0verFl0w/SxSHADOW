"""
output.csv_export
SIEM-ready CSV export of ranked HijackCandidate objects.

Schema is stable and column-ordered for ingestion by Splunk / Sentinel /
Elastic. One row per (host_binary, hijackable_dll) pair. Columns map
cleanly onto MITRE T1574.002 (DLL Side-Loading) detection content.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable

from core import HijackCandidate, ScanResult

# MITRE technique IDs covered by detections derived from this CSV
_MITRE_TECHNIQUE = "T1574.002"
_MITRE_TACTICS   = "TA0005,TA0003,TA0004"   # Defense Evasion / Persistence / PrivEsc

_COLUMNS = [
    "host_binary",
    "host_arch",
    "host_signed",
    "host_publisher",
    "host_sha256",
    "host_winsxs_path",
    "component_name",
    "component_version",
    "hijackable_dll",
    "real_dll_path",
    "real_dll_sha256",
    "real_dll_export_count",
    "delay_loaded",
    "known_abused",
    "defensive_priority",
    "priority_known_abuse",
    "priority_stealth",
    "priority_exposure",
    "mitre_technique",
    "mitre_tactics",
]


def emit_csv(result: ScanResult, out_path: Path) -> int:
    """
    Write all candidates from result to a CSV at out_path. Returns row count.
    Uses the dialect Excel and most SIEMs auto-detect.
    """
    rows_written = 0
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for c in result.candidates:
            d = c.defensive_breakdown or {}
            writer.writerow({
                "host_binary":           c.binary_name,
                "host_arch":             c.binary_arch,
                "host_signed":           ("true" if c.binary_signed is True
                                          else "false" if c.binary_signed is False
                                          else ""),
                "host_publisher":        c.binary_publisher or "",
                "host_sha256":           c.binary_sha256 or "",
                "host_winsxs_path":      str(c.binary_path),
                "component_name":        c.component_name,
                "component_version":     c.component_version,
                "hijackable_dll":        c.hijackable_dll,
                "real_dll_path":         str(c.real_dll_path) if c.real_dll_path else "",
                "real_dll_sha256":       c.real_dll_sha256 or "",
                "real_dll_export_count": len(c.real_dll_exports),
                "delay_loaded":          "true" if c.delay_loaded else "false",
                "known_abused":          "true" if c.known_abused else "false",
                "defensive_priority":    c.defensive_priority,
                "priority_known_abuse":  d.get("known_abuse", 0),
                "priority_stealth":      d.get("stealth", 0),
                "priority_exposure":     d.get("exposure", 0),
                "mitre_technique":       _MITRE_TECHNIQUE,
                "mitre_tactics":         _MITRE_TACTICS,
            })
            rows_written += 1
    return rows_written


def emit_baseline_csv(
    candidates: Iterable[HijackCandidate],
    out_path: Path,
) -> int:
    """
    Compact "expected good" baseline: per host binary, the DLL names and
    hashes a defender should see when the binary runs from its WinSxS
    folder. Pair this with the main detection CSV so an analyst can
    quickly tell legitimate-but-redistributed from malicious.
    """
    cols = ["host_binary", "host_winsxs_path", "host_sha256",
            "expected_dll", "expected_dll_path", "expected_dll_sha256"]
    rows = 0
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=cols)
        writer.writeheader()
        for c in candidates:
            writer.writerow({
                "host_binary":          c.binary_name,
                "host_winsxs_path":     str(c.binary_path),
                "host_sha256":          c.binary_sha256 or "",
                "expected_dll":         c.hijackable_dll,
                "expected_dll_path":    str(c.real_dll_path) if c.real_dll_path else "",
                "expected_dll_sha256":  c.real_dll_sha256 or "",
            })
            rows += 1
    return rows
