"""
WRAITH — core.pe_parser
Thin pefile wrappers for import/export parsing, architecture detection,
.NET assembly detection, and Authenticode signature checking.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import hashlib
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Tuple

import pefile

from core import ExportEntry

# pefile data-directory indices
_DIR_EXPORT       = 0
_DIR_IMPORT       = 1
_DIR_DELAY_IMPORT = 13
_DIR_CLR          = 14   # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR

# PE machine-type constants
_MACHINE_X86   = 0x014C
_MACHINE_X64   = 0x8664
_MACHINE_ARM64 = 0xAA64


def get_imports(path: Path) -> List[Tuple[str, bool]]:
    """
    Return (dll_name_lower, is_delay_loaded) pairs from the PE import tables.
    Both the regular import table and the delay-import table are parsed.
    Returns an empty list on any parse error.
    """
    results: List[Tuple[str, bool]] = []
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[_DIR_IMPORT, _DIR_DELAY_IMPORT])

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    name = entry.dll.decode("utf-8", errors="ignore").lower()
                    if name:
                        results.append((name, False))
                except Exception:
                    continue

        if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                try:
                    name = entry.dll.decode("utf-8", errors="ignore").lower()
                    if name:
                        results.append((name, True))
                except Exception:
                    continue

        pe.close()
    except Exception:
        pass

    # Deduplicate while preserving delay-load flag for each unique name
    seen: dict[str, bool] = {}
    for name, delay in results:
        if name not in seen:
            seen[name] = delay
    return list(seen.items())


def get_exports(path: Path) -> List[ExportEntry]:
    """
    Return all exported symbols from a PE file.
    Ordinal-only exports have name == "".
    Returns an empty list on any error.
    """
    exports: List[ExportEntry] = []
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[_DIR_EXPORT])

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    name = sym.name.decode("utf-8", errors="ignore") if sym.name else ""
                    exports.append(ExportEntry(
                        name=name,
                        ordinal=sym.ordinal,
                        address=sym.address or 0,
                    ))
                except Exception:
                    continue

        pe.close()
    except Exception:
        pass

    return exports


def get_arch(path: Path) -> str:
    """
    Return "x64", "x86", "arm64", or "unknown" based on PE machine type.
    """
    try:
        pe = pefile.PE(str(path), fast_load=True)
        machine = pe.FILE_HEADER.Machine
        pe.close()
        return {
            _MACHINE_X86:   "x86",
            _MACHINE_X64:   "x64",
            _MACHINE_ARM64: "arm64",
        }.get(machine, "unknown")
    except Exception:
        return "unknown"


def is_net_assembly(path: Path) -> bool:
    """
    Return True if the PE has a CLR (COM_DESCRIPTOR) header, indicating
    it is a managed .NET assembly.
    """
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[_DIR_CLR])
        result = (
            hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR")
            and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR is not None
            and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.VirtualAddress != 0
        )
        pe.close()
        return result
    except Exception:
        return False


# ── Authenticode (native WinVerifyTrust) ─────────────────────────────────────
#
# Calling Get-AuthenticodeSignature per binary spawns ~200-800 ms of PowerShell
# overhead each — unusable across 10k WinSxS binaries. We use WinTrust.dll
# directly via ctypes: same authority, no subprocess, no string interpolation.

_WTD_UI_NONE             = 2
_WTD_REVOKE_NONE         = 0
_WTD_CHOICE_FILE         = 1
_WTD_STATEACTION_VERIFY  = 1
_WTD_STATEACTION_CLOSE   = 2
_WTD_SAFER_FLAG          = 0x100

# {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
_WINTRUST_ACTION_GENERIC_VERIFY_V2 = (
    0x00AAC56B, 0xCD44, 0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct",       wt.DWORD),
        ("pcwszFilePath",  wt.LPCWSTR),
        ("hFile",          wt.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct",            wt.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData",      ctypes.c_void_p),
        ("dwUIChoice",          wt.DWORD),
        ("fdwRevocationChecks", wt.DWORD),
        ("dwUnionChoice",       wt.DWORD),
        ("pFile",               ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ("dwStateAction",       wt.DWORD),
        ("hWVTStateData",       wt.HANDLE),
        ("pwszURLReference",    wt.LPCWSTR),
        ("dwProvFlags",         wt.DWORD),
        ("dwUIContext",         wt.DWORD),
        ("pSignatureSettings",  ctypes.c_void_p),
    ]


# ── Catalog-signature support (modern Windows binaries are catalog-signed) ───
#
# Get-AuthenticodeSignature treats a catalog-signed file as Valid. A pure
# WinVerifyTrust(file) call does NOT — it only looks at the embedded sig.
# So we replicate the catalog enumeration the OS does:
#   1. CryptCATAdminAcquireContext
#   2. CryptCATAdminCalcHashFromFileHandle
#   3. CryptCATAdminEnumCatalogFromHash → catalog .cat path
#   4. WinVerifyTrust with WINTRUST_CATALOG_INFO

_WTD_CHOICE_CATALOG = 2
_INVALID_HANDLE     = wt.HANDLE(-1).value
_GENERIC_READ       = 0x80000000
_OPEN_EXISTING      = 3
_FILE_SHARE_READ    = 1


class _CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct",        wt.DWORD),
        ("wszCatalogFile",  ctypes.c_wchar * 260),
    ]


class _WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct",           wt.DWORD),
        ("dwCatalogVersion",   wt.DWORD),
        ("pcwszCatalogFilePath", wt.LPCWSTR),
        ("pcwszMemberTag",      wt.LPCWSTR),
        ("pcwszMemberFilePath", wt.LPCWSTR),
        ("hMemberFile",        wt.HANDLE),
        ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCalculatedFileHash", wt.DWORD),
        ("pcCatalogContext",   ctypes.c_void_p),
        ("hCatAdmin",          wt.HANDLE),
    ]


try:
    _wintrust = ctypes.WinDLL("wintrust.dll")
    _WinVerifyTrust = _wintrust.WinVerifyTrust
    _WinVerifyTrust.restype  = ctypes.c_long
    _WinVerifyTrust.argtypes = [wt.HWND, ctypes.POINTER(_GUID),
                                ctypes.POINTER(_WINTRUST_DATA)]

    _CryptCATAdminAcquireContext = _wintrust.CryptCATAdminAcquireContext
    _CryptCATAdminAcquireContext.restype  = wt.BOOL
    _CryptCATAdminAcquireContext.argtypes = [
        ctypes.POINTER(wt.HANDLE), ctypes.POINTER(_GUID), wt.DWORD,
    ]

    _CryptCATAdminReleaseContext = _wintrust.CryptCATAdminReleaseContext
    _CryptCATAdminReleaseContext.restype  = wt.BOOL
    _CryptCATAdminReleaseContext.argtypes = [wt.HANDLE, wt.DWORD]

    _CryptCATAdminCalcHashFromFileHandle = (
        _wintrust.CryptCATAdminCalcHashFromFileHandle
    )
    _CryptCATAdminCalcHashFromFileHandle.restype  = wt.BOOL
    _CryptCATAdminCalcHashFromFileHandle.argtypes = [
        wt.HANDLE, ctypes.POINTER(wt.DWORD),
        ctypes.POINTER(ctypes.c_ubyte), wt.DWORD,
    ]

    _CryptCATAdminEnumCatalogFromHash = (
        _wintrust.CryptCATAdminEnumCatalogFromHash
    )
    _CryptCATAdminEnumCatalogFromHash.restype  = wt.HANDLE
    _CryptCATAdminEnumCatalogFromHash.argtypes = [
        wt.HANDLE, ctypes.POINTER(ctypes.c_ubyte), wt.DWORD,
        wt.DWORD, ctypes.POINTER(wt.HANDLE),
    ]

    _CryptCATCatalogInfoFromContext = _wintrust.CryptCATCatalogInfoFromContext
    _CryptCATCatalogInfoFromContext.restype  = wt.BOOL
    _CryptCATCatalogInfoFromContext.argtypes = [
        wt.HANDLE, ctypes.POINTER(_CATALOG_INFO), wt.DWORD,
    ]

    _CryptCATAdminReleaseCatalogContext = (
        _wintrust.CryptCATAdminReleaseCatalogContext
    )
    _CryptCATAdminReleaseCatalogContext.restype  = wt.BOOL
    _CryptCATAdminReleaseCatalogContext.argtypes = [
        wt.HANDLE, wt.HANDLE, wt.DWORD,
    ]

    _kernel32 = ctypes.WinDLL("kernel32.dll")
    _CreateFileW = _kernel32.CreateFileW
    _CreateFileW.restype  = wt.HANDLE
    _CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD,
                             ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE]
    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.restype  = wt.BOOL
    _CloseHandle.argtypes = [wt.HANDLE]

    _HAVE_WINTRUST = True
except Exception:
    _HAVE_WINTRUST = False


def _verify_embedded(path: Path) -> int:
    """Run WinVerifyTrust against the embedded signature. Returns LONG status."""
    file_info = _WINTRUST_FILE_INFO()
    file_info.cbStruct       = ctypes.sizeof(_WINTRUST_FILE_INFO)
    file_info.pcwszFilePath  = str(path)
    file_info.hFile          = None
    file_info.pgKnownSubject = None

    guid = _GUID(*_WINTRUST_ACTION_GENERIC_VERIFY_V2)
    data = _WINTRUST_DATA()
    data.cbStruct            = ctypes.sizeof(_WINTRUST_DATA)
    data.dwUIChoice          = _WTD_UI_NONE
    data.fdwRevocationChecks = _WTD_REVOKE_NONE
    data.dwUnionChoice       = _WTD_CHOICE_FILE
    data.pFile               = ctypes.pointer(file_info)
    data.dwStateAction       = _WTD_STATEACTION_VERIFY
    data.dwProvFlags         = _WTD_SAFER_FLAG

    status = _WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data))
    data.dwStateAction = _WTD_STATEACTION_CLOSE
    _WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data))
    return status


def _verify_via_catalog(path: Path) -> Optional[bool]:
    """
    Catalog-signed verification path. Returns True if a trusted catalog
    contains this file's hash, False if no catalog claims it, None on error.
    """
    h_cat_admin = wt.HANDLE()
    if not _CryptCATAdminAcquireContext(
        ctypes.byref(h_cat_admin), None, 0
    ):
        return None

    file_handle = _CreateFileW(
        str(path), _GENERIC_READ, _FILE_SHARE_READ,
        None, _OPEN_EXISTING, 0, None,
    )
    if file_handle == _INVALID_HANDLE or file_handle is None:
        _CryptCATAdminReleaseContext(h_cat_admin, 0)
        return None

    try:
        hash_size = wt.DWORD(0)
        # First call: query required size
        _CryptCATAdminCalcHashFromFileHandle(
            file_handle, ctypes.byref(hash_size), None, 0
        )
        if hash_size.value == 0:
            return False

        hash_buf = (ctypes.c_ubyte * hash_size.value)()
        if not _CryptCATAdminCalcHashFromFileHandle(
            file_handle, ctypes.byref(hash_size), hash_buf, 0
        ):
            return False

        cat_ctx = _CryptCATAdminEnumCatalogFromHash(
            h_cat_admin, hash_buf, hash_size.value, 0, None
        )
        if not cat_ctx:
            # No catalog claims this file
            return False

        cat_info = _CATALOG_INFO()
        cat_info.cbStruct = ctypes.sizeof(_CATALOG_INFO)
        ok = _CryptCATCatalogInfoFromContext(
            cat_ctx, ctypes.byref(cat_info), 0
        )
        _CryptCATAdminReleaseCatalogContext(h_cat_admin, cat_ctx, 0)
        if not ok or not cat_info.wszCatalogFile:
            return False

        # Verify the catalog with WinVerifyTrust
        cat_member = _WINTRUST_CATALOG_INFO()
        cat_member.cbStruct             = ctypes.sizeof(_WINTRUST_CATALOG_INFO)
        cat_member.pcwszCatalogFilePath = cat_info.wszCatalogFile
        cat_member.pcwszMemberFilePath  = str(path)
        # Hex-encoded hash as member tag
        tag = "".join(f"{b:02X}" for b in bytes(hash_buf))
        cat_member.pcwszMemberTag       = tag
        cat_member.pbCalculatedFileHash = hash_buf
        cat_member.cbCalculatedFileHash = hash_size.value
        cat_member.hMemberFile          = file_handle

        guid = _GUID(*_WINTRUST_ACTION_GENERIC_VERIFY_V2)
        data = _WINTRUST_DATA()
        data.cbStruct            = ctypes.sizeof(_WINTRUST_DATA)
        data.dwUIChoice          = _WTD_UI_NONE
        data.fdwRevocationChecks = _WTD_REVOKE_NONE
        data.dwUnionChoice       = _WTD_CHOICE_CATALOG
        data.pFile               = ctypes.cast(
            ctypes.pointer(cat_member),
            ctypes.POINTER(_WINTRUST_FILE_INFO),
        )
        data.dwStateAction       = _WTD_STATEACTION_VERIFY
        data.dwProvFlags         = _WTD_SAFER_FLAG

        status = _WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data))
        data.dwStateAction = _WTD_STATEACTION_CLOSE
        _WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data))
        return status == 0
    finally:
        _CloseHandle(file_handle)
        _CryptCATAdminReleaseContext(h_cat_admin, 0)


def is_signed(path: Path) -> Optional[bool]:
    """
    Check Authenticode signature via WinTrust.dll.

    Embedded signature first; falls back to catalog signature (the source
    of trust for most Windows-shipped binaries — notepad, svchost, etc).

    Returns
    -------
    True  — file has a valid signature (embedded or catalog)
    False — file is unsigned or chain not trusted
    None  — check could not be completed (API unavailable / OS error)
    """
    if not _HAVE_WINTRUST:
        return None

    try:
        # 0 = TRUST_SUCCESS; non-zero means no embedded sig or invalid chain.
        if _verify_embedded(path) == 0:
            return True

        cat_result = _verify_via_catalog(path)
        if cat_result is True:
            return True
        if cat_result is False:
            return False
        return None
    except Exception:
        return None


def get_publisher(path: Path) -> Optional[str]:
    """
    Return the Authenticode subject CN (e.g. "Microsoft Windows") or None.

    Uses PowerShell Get-AuthenticodeSignature once per call. Caller should
    only invoke this for binaries that already verified as signed, since
    spawning PS is expensive. Path is passed via -LiteralPath to neutralise
    any quoting issues.
    """
    try:
        # -LiteralPath takes the value as-is; we pass it as a separate argv
        # element so PowerShell never has to parse it as a script literal.
        ps_script = (
            "$ErrorActionPreference='Stop';"
            "$s=Get-AuthenticodeSignature -LiteralPath $args[0];"
            "if ($s.SignerCertificate) { $s.SignerCertificate.Subject } "
            "else { '' }"
        )
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile",
             "-Command", ps_script, "--", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=0x08000000,   # CREATE_NO_WINDOW
        )
        subject = result.stdout.strip()
        if not subject:
            return None
        # Subject looks like: CN=Microsoft Windows, O=Microsoft Corporation, ...
        for part in subject.split(","):
            part = part.strip()
            if part.upper().startswith("CN="):
                return part[3:].strip()
        return subject
    except Exception:
        return None


# ── File hashing ─────────────────────────────────────────────────────────────

@lru_cache(maxsize=4096)
def sha256_file(path: Path) -> Optional[str]:
    """SHA-256 of a file, cached by path. Returns None on I/O error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None
