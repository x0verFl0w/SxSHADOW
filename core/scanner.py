"""
SxSHADOW — core.scanner
Walks C:\\Windows\\WinSxS, finds candidate binaries, correlates import tables
against KnownDLLs, deduplicates across version folders, and returns ranked
HijackCandidates.

Performance design
------------------
Phase 1  serial     Collect all binary paths from WinSxS tree  (~0.5 s)
Phase 2  parallel   PE-parse each binary — no WinVerifyTrust    (~5-10 s)
Phase 3  serial     Dedup by (binary_name, dll_name), rank       (<1 s)
Phase 4  serial     WinVerifyTrust ONLY for unique finalist bins  (~3-5 s)
Phase 5  serial     score_defensive on all candidates             (<1 s)

WHY sign check is moved to Phase 4
    CryptCATAdminEnumCatalogFromHash does disk I/O through the Windows
    catalog database.  On a typical system this takes 0.5–2 s per file.
    Applying it to all 12 k+ WinSxS binaries in Phase 2 produces the
    ~2 300 s total observed on first run.  All WinSxS binaries are placed
    by the Component-Based Servicing stack (TrustedInstaller) and are
    Microsoft-signed by construction, so Phase 2 sets binary_signed=True
    by convention and Phase 4 confirms just the unique winner binary names.
"""
from __future__ import annotations

import hashlib
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from rich.console import Console
from rich.progress import (BarColumn, Progress, SpinnerColumn,
                           TaskProgressColumn, TextColumn, TimeElapsedColumn)

from core import ExportEntry, HijackCandidate, ScanResult
from core.hijacklibs import is_known_abused
from core.manifest import get_manifest, is_manifest_bound
from core.pe_parser import (get_arch, get_exports, get_imports, get_publisher,
                             is_signed, sha256_file)
from core.resolver import can_hijack, find_system_dll, load_known_dlls
from core.scorer import rank, score, score_defensive

# ── Constants ────────────────────────────────────────────────────────────────

WINSXS_PATH = Path(r"C:\Windows\WinSxS")

_FOLDER_RE = re.compile(
    r"^(?P<arch>[^_]+)_(?P<name>.+?)_(?P<token>[0-9a-f]{16})_"
    r"(?P<version>[\d.]+)_(?P<culture>[^_]+)_(?P<hash>[0-9a-f]+)$",
    re.IGNORECASE,
)
_ARCH_MAP: dict[str, str] = {"amd64": "x64", "x86": "x86", "wow64": "x86"}

_STAGING_PATHS: List[str] = [
    r"C:\ProgramData\WindowsDefenderUpdate",
    r"C:\ProgramData\MicrosoftEdgeUpdate",
    r"C:\ProgramData\WindowsUpdate",
    r"C:\ProgramData\MicrosoftDotNetFramework",
    r"C:\ProgramData\NuGetPackages",
    r"C:\ProgramData\NETFrameworkCache",
    r"C:\Users\Public\MicrosoftUpdate",
]

_stderr = Console(stderr=True)


# ── Internal data structures ──────────────────────────────────────────────────

@dataclass
class _FolderInfo:
    arch: str
    name: str
    version: str
    folder: Path


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_folder(folder: Path) -> Optional[_FolderInfo]:
    m = _FOLDER_RE.match(folder.name)
    if not m:
        return None
    raw = m.group("arch").lower()
    if raw == "msil":
        return None
    arch = _ARCH_MAP.get(raw, raw)
    return _FolderInfo(arch=arch, name=m.group("name"),
                       version=m.group("version"), folder=folder)


def _iter_binary_paths(
    winsxs: Path,
    arch_filter: Optional[str],
    include_dlls: bool = True,
) -> List[Tuple[Path, _FolderInfo]]:
    suffixes = {".exe", ".dll"} if include_dlls else {".exe"}
    results: List[Tuple[Path, _FolderInfo]] = []
    try:
        for entry in winsxs.iterdir():
            if not entry.is_dir():
                continue
            info = _parse_folder(entry)
            if info is None:
                continue
            if arch_filter and info.arch != arch_filter:
                continue
            try:
                for child in entry.iterdir():
                    if child.suffix.lower() in suffixes and child.is_file():
                        results.append((child, info))
            except (PermissionError, OSError):
                continue
    except (PermissionError, OSError):
        pass
    return results


# Back-compat alias
_iter_exe_paths = _iter_binary_paths


# ── Per-DLL export cache (shared across threads) ─────────────────────────────

_EXPORTS_CACHE: Dict[str, List[ExportEntry]] = {}
_EXPORTS_LOCK = threading.Lock()


def _cached_exports(real_dll_path: Optional[Path]) -> List[ExportEntry]:
    if real_dll_path is None:
        return []
    key = str(real_dll_path).lower()
    with _EXPORTS_LOCK:
        cached = _EXPORTS_CACHE.get(key)
        if cached is not None:
            return cached
    exports = get_exports(real_dll_path)
    with _EXPORTS_LOCK:
        _EXPORTS_CACHE[key] = exports
    return exports


def _choose_staging(binary_name: str) -> str:
    idx = int(hashlib.md5(binary_name.lower().encode()).hexdigest(), 16) % len(_STAGING_PATHS)
    return _STAGING_PATHS[idx]


# ── Per-binary worker (Phase 2, runs in thread pool) ─────────────────────────

def _process_binary_fast(
    bin_path: Path,
    info: _FolderInfo,
    known_dlls: Set[str],
    collect_hashes: bool,
) -> List[HijackCandidate]:
    """
    Fast path — NO WinVerifyTrust call.

    All binaries inside C:\\Windows\\WinSxS are placed by the Windows Component-
    Based Servicing (CBS) stack which validates Authenticode before installation.
    We set binary_signed=True by construction; Phase 4 of scan() confirms this
    for the actual finalist binaries with a real WinVerifyTrust call.
    """
    imports = get_imports(bin_path)
    if not imports:
        return []

    arch     = get_arch(bin_path)
    bin_sha  = sha256_file(bin_path) if collect_hashes else None

    candidates: List[HijackCandidate] = []
    for dll_name, delay_loaded in imports:
        # can_hijack with binary_path triggers the manifest-bound check
        if not can_hijack(dll_name, known_dlls, bin_path):
            continue

        real_path    = find_system_dll(dll_name, arch=arch if arch in ("x64", "x86") else "x64")
        real_exports = _cached_exports(real_path)
        real_sha     = sha256_file(real_path) if collect_hashes and real_path else None

        candidates.append(HijackCandidate(
            binary_path=bin_path,
            binary_arch=arch,
            binary_signed=True,         # WinSxS convention; confirmed in Phase 4
            binary_name=bin_path.name,
            component_name=info.name,
            component_version=info.version,
            hijackable_dll=dll_name,
            real_dll_path=real_path,
            real_dll_exports=real_exports,
            delay_loaded=delay_loaded,
            suggested_drop_path=_choose_staging(bin_path.name),
            binary_sha256=bin_sha,
            real_dll_sha256=real_sha,
            binary_publisher=None,
            manifest_bound=False,       # by construction — filtered above
            known_abused=is_known_abused(dll_name),
        ))

    return candidates


# ── Dedup helper ──────────────────────────────────────────────────────────────

def _dedup_key(c: HijackCandidate) -> str:
    return f"{c.binary_name.lower()}|{c.hijackable_dll.lower()}"


def _better(incumbent: HijackCandidate, challenger: HijackCandidate) -> bool:
    """Return True if challenger should replace incumbent in the dedup map."""
    # Prefer a candidate where we found the real DLL (proxy will actually work)
    if incumbent.real_dll_path is None and challenger.real_dll_path is not None:
        return True
    # Prefer non-delay-loaded (fires at process attach, more reliable)
    if incumbent.delay_loaded and not challenger.delay_loaded:
        return True
    return False


# ── Public API ────────────────────────────────────────────────────────────────

def scan(
    winsxs_path: Path = WINSXS_PATH,
    arch_filter: Optional[str] = None,
    max_workers: int = 8,
    sign_check: bool = True,
    max_candidates: Optional[int] = None,
    top_n: Optional[int] = None,
    include_dlls: bool = True,
    collect_publisher: bool = False,
    collect_hashes: bool = False,
    on_candidate: Optional[Callable[[HijackCandidate, int], None]] = None,
) -> ScanResult:
    """
    Full WinSxS scan.

    Parameters
    ----------
    winsxs_path:        Root of the Windows component store.
    arch_filter:        "x64" | "x86" | None (both).
    max_workers:        Thread pool size for parallel PE parsing.
    sign_check:         Run WinVerifyTrust on finalist binary names only
                        (not every binary in WinSxS). Disable with --no-sign-check.
    max_candidates:     Cap on total returned candidates (None = all unique pairs).
    top_n:              Stop scanning early once top_n×3 unique (binary,dll)
                        pairs have been found. Also caps final results to top_n.
                        Pass args.top here to make --top 3 actually stop early.
    include_dlls:       Also scan DLL hosts, not just EXEs.
    collect_publisher:  Resolve Authenticode publisher CN (spawns PowerShell).
    collect_hashes:     SHA-256 of each host binary and real DLL. Slow but
                        required for --baseline-csv and --csv output. Default False.
    on_candidate:       Callback(candidate, rank_so_far) fired for each new unique
                        pair as it is discovered. Use for live console streaming.

    Returns
    -------
    ScanResult with candidates sorted descending by composite score.

    Performance notes
    -----------------
    Default (top_n=10, no hashes): ~5-10 s
    Full scan (top_n=None, no hashes): ~15-30 s
    Full scan (top_n=None, collect_hashes=True): ~30-60 s
    """
    t0 = time.monotonic()

    # Phase 1 ─ collect binary paths (serial, fast)
    known_dlls  = load_known_dlls()
    binary_list = _iter_binary_paths(winsxs_path, arch_filter, include_dlls)
    total       = len(binary_list)

    # Dedup map: key → best HijackCandidate seen so far
    unique: Dict[str, HijackCandidate] = {}

    # How many unique pairs to collect before declaring "enough to rank"
    early_stop = (top_n * 3) if top_n else (max_candidates * 3 if max_candidates else None)
    stop_flag  = threading.Event()

    # Phase 2 ─ parallel PE parsing (no WinVerifyTrust)
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=36),
        TaskProgressColumn(),
        TextColumn("[dim]unique: {task.fields[hits]}"),
        TimeElapsedColumn(),
        console=_stderr,
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"SxSHADOW fast-scan  {total:,} binaries",
            total=total, hits=0,
        )

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(
                    _process_binary_fast, bp, info, known_dlls, collect_hashes
                ): bp
                for bp, info in binary_list
            }

            for future in as_completed(futures):
                if stop_flag.is_set():
                    future.cancel()
                    progress.advance(task)
                    continue

                progress.advance(task)
                try:
                    batch = future.result(timeout=15)
                    for c in batch:
                        key = _dedup_key(c)
                        if key not in unique:
                            unique[key] = c
                            progress.update(task, hits=len(unique))
                            if on_candidate:
                                on_candidate(c, len(unique))
                        elif _better(unique[key], c):
                            unique[key] = c
                except Exception:
                    pass

                if early_stop and len(unique) >= early_stop:
                    stop_flag.set()

    # Phase 3 ─ rank unique candidates
    ranked = rank(list(unique.values()))

    # Phase 4 ─ confirm signatures for finalist unique binary names only
    if sign_check and ranked:
        finalist_count = (top_n or max_candidates or 20)
        seen_bins: Set[str] = set()
        for c in ranked[:finalist_count]:
            bk = c.binary_name.lower()
            if bk in seen_bins:
                continue
            seen_bins.add(bk)
            actual = is_signed(c.binary_path)
            # Propagate result to ALL candidates sharing this binary name
            for other in ranked:
                if other.binary_name.lower() == bk:
                    other.binary_signed = actual
        # Re-score with verified signature flags, re-sort
        for c in ranked:
            score(c)
        ranked.sort(key=lambda c: c.score, reverse=True)

    # Phase 5 ─ defensive scoring (independent axis, fast)
    for c in ranked:
        score_defensive(c)

    # Optional: publisher CN (spawns PowerShell — only for a few finalists)
    if collect_publisher and ranked:
        pub_n = top_n or max_candidates or 5
        seen_bins = set()
        for c in ranked[:pub_n]:
            bk = c.binary_name.lower()
            if bk in seen_bins or c.binary_signed is not True:
                continue
            seen_bins.add(bk)
            pub = get_publisher(c.binary_path)
            for other in ranked:
                if other.binary_name.lower() == bk:
                    other.binary_publisher = pub

    # Apply final cap
    cap = top_n or max_candidates
    if cap:
        ranked = ranked[:cap]

    return ScanResult(
        candidates=ranked,
        total_binaries_examined=total,
        winsxs_path=winsxs_path,
        scan_duration_seconds=time.monotonic() - t0,
    )
