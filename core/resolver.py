"""
WRAITH — core.resolver
DLL search-order resolution and KnownDLLs registry check.

KnownDLLs are loaded from a system-controlled path and are therefore immune
to application-directory hijacking.  Any DLL not in KnownDLLs and not loaded
via an absolute/activation-context path is a candidate.
"""
from __future__ import annotations

import os
import winreg
from functools import lru_cache
from pathlib import Path
from typing import Optional, Set

# Populated at first call to load_known_dlls(); modules import this symbol
# directly so they get the live set after initialisation.
KNOWN_DLLS: Set[str] = set()

_WINDOWS_ROOT = Path(os.environ.get("SystemRoot", r"C:\Windows"))

# Architecture-aware search order. WinSxS binaries are mostly 64-bit; 32-bit
# components are silently redirected through WoW64. The previous code searched
# System32 first regardless and picked the wrong "real DLL" for x86 binaries
# when System32 and SysWOW64 both held a copy with different exports.
SYSTEM_SEARCH_DIRS_X64: list[Path] = [
    _WINDOWS_ROOT / "System32",
    _WINDOWS_ROOT,
]
SYSTEM_SEARCH_DIRS_X86: list[Path] = [
    _WINDOWS_ROOT / "SysWOW64",
    _WINDOWS_ROOT,
]

# Back-compat alias; existing callers that don't pass arch get the x64 list.
SYSTEM_SEARCH_DIRS: list[Path] = SYSTEM_SEARCH_DIRS_X64

# Virtual DLL prefixes — API sets, not real files, never hijackable.
# "api-ms-" already subsumes "api-ms-win-"; same for ext-ms-.
_VIRTUAL_PREFIXES = ("api-ms-", "ext-ms-")

# Always-safe DLLs (loaded before user code can place one)
_ALWAYS_SAFE = frozenset({
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "user32.dll",
    "win32u.dll",
})

_KNOWNDLLS_KEY = (
    r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs"
)


def load_known_dlls() -> Set[str]:
    """
    Read HKLM\\...\\KnownDLLs and return a lower-case set of DLL filenames.
    The global KNOWN_DLLS is updated in place and also returned.
    Silently returns the current set on any registry error.
    """
    global KNOWN_DLLS
    found: Set[str] = set()
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _KNOWNDLLS_KEY)
        i = 0
        while True:
            try:
                _name, value, _type = winreg.EnumValue(key, i)
                if isinstance(value, str) and value.lower().endswith(".dll"):
                    found.add(value.lower())
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except Exception:
        pass

    # Always include the permanently-safe set regardless of registry content
    found |= _ALWAYS_SAFE
    KNOWN_DLLS = found
    return found


def is_known_dll(dll_name: str, known: Optional[Set[str]] = None) -> bool:
    """
    Return True if dll_name is in the KnownDLLs set (and thus cannot be
    hijacked via application-directory placement).
    Falls back to the module-level KNOWN_DLLS if known is not provided.
    """
    pool = known if known is not None else KNOWN_DLLS
    return dll_name.lower() in pool


@lru_cache(maxsize=4096)
def find_system_dll(dll_name: str, arch: str = "x64") -> Optional[Path]:
    """
    Search the arch-appropriate system directories for dll_name.
    Returns the first match, or None if the DLL isn't present on this system.

    NTFS is case-insensitive, so Path.exists() handles casing — no iterdir
    fallback needed.
    """
    search_dirs = (SYSTEM_SEARCH_DIRS_X86 if arch == "x86"
                   else SYSTEM_SEARCH_DIRS_X64)
    for search_dir in search_dirs:
        candidate = search_dir / dll_name
        try:
            if candidate.is_file():
                return candidate
        except (PermissionError, OSError):
            continue
    return None


def can_hijack(
    dll_name: str,
    known_dlls: Set[str],
    binary_path: Optional[Path] = None,
) -> bool:
    """
    Return True if dll_name passes all hijackability filters:

    1. Not in KnownDLLs — loaded from a fixed trusted path.
    2. Not a virtual API set (api-ms-*, ext-ms-*) — resolved in-process.
    3. Not in the always-safe set (ntdll, kernel32, kernelbase).
    4. Not bound by the binary's SxS manifest (activation-context binding
       locks the import to a specific component path and bypasses the
       application-directory search order).

    Filter 4 requires binary_path; if omitted, the manifest check is skipped
    and the caller is responsible for filtering separately. This keeps the
    function backwards-compatible with existing call sites.
    """
    name_lower = dll_name.lower()

    if name_lower in known_dlls:
        return False
    if any(name_lower.startswith(pfx) for pfx in _VIRTUAL_PREFIXES):
        return False
    if name_lower in _ALWAYS_SAFE:
        return False

    if binary_path is not None:
        # Import here to avoid a circular import at module load
        from core.manifest import is_manifest_bound
        if is_manifest_bound(binary_path, name_lower):
            return False

    return True
