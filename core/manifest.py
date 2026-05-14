"""
core.manifest
WinSxS / side-by-side manifest parsing.

A binary inside WinSxS typically ships with a manifest that declares
its dependent assemblies and explicitly-loaded files. When an import is
satisfied by the activation context (a <file name="x.dll"> entry or a
<dependentAssembly> resolution), Windows binds it to a specific component
under WinSxS and the normal "application directory first" search order
does NOT apply — the import is not exposed to application-directory
hijacking.

Skipping manifest checks is the #1 source of false positives in static
WinSxS hijack scanners. This module gives the scanner the data it needs
to filter those out.

Manifest sources, in order of precedence:
  1. PE resource: type RT_MANIFEST (24), id 1 (exe) or 2 (dll)
  2. External file:  <binary>.manifest next to the binary
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Set

import pefile

# Resource type RT_MANIFEST and standard manifest IDs
_RT_MANIFEST       = 24
_MANIFEST_ID_EXE   = 1
_MANIFEST_ID_DLL   = 2

# All asmv1/asmv2/asmv3 namespaces collapse to the same element local-names
_NS_STRIP = {"urn:schemas-microsoft-com:asm.v1",
             "urn:schemas-microsoft-com:asm.v2",
             "urn:schemas-microsoft-com:asm.v3"}


@dataclass
class ManifestInfo:
    """Parsed view of a WinSxS manifest."""
    has_manifest: bool = False
    # DLLs declared via <file name="..."> — bound to this component's dir.
    bound_files: Set[str] = field(default_factory=set)
    # <dependentAssembly> names that resolve to a sibling WinSxS component.
    dependent_assemblies: List[str] = field(default_factory=list)

    def binds(self, dll_name: str) -> bool:
        """True if the manifest binds dll_name to a non-hijackable location."""
        return dll_name.lower() in self.bound_files


# ── Internal helpers ─────────────────────────────────────────────────────────

def _local(tag: str) -> str:
    """Strip namespace from an ElementTree tag like '{ns}file' -> 'file'."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _parse_xml(blob: bytes) -> Optional[ManifestInfo]:
    """Parse manifest XML bytes into a ManifestInfo, or None on error."""
    try:
        # Manifests are UTF-8 or UTF-16. ElementTree auto-detects via the
        # XML decl, but some have a UTF-8 BOM that confuses it.
        if blob.startswith(b"\xef\xbb\xbf"):
            blob = blob[3:]
        root = ET.fromstring(blob)
    except ET.ParseError:
        return None

    info = ManifestInfo(has_manifest=True)
    for elem in root.iter():
        name = _local(elem.tag)
        if name == "file":
            fn = elem.attrib.get("name") or elem.attrib.get("Name")
            if fn:
                info.bound_files.add(fn.lower())
        elif name == "assemblyIdentity":
            # Only count assemblyIdentity inside dependentAssembly
            parent_local = None
            # ET doesn't expose parents; we collect both and dedupe below.
            asm_name = elem.attrib.get("name")
            if asm_name:
                info.dependent_assemblies.append(asm_name.lower())
    # Dedupe dependent_assemblies preserving order
    seen: Set[str] = set()
    info.dependent_assemblies = [
        n for n in info.dependent_assemblies
        if not (n in seen or seen.add(n))
    ]
    return info


def _read_embedded_manifest(path: Path) -> Optional[bytes]:
    """
    Extract the RT_MANIFEST resource from a PE if present.
    Returns the raw XML bytes or None if no manifest is embedded.
    """
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
    except Exception:
        return None

    blob: Optional[bytes] = None
    try:
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return None

        for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_id = getattr(type_entry, "id", None)
            if type_id != _RT_MANIFEST:
                continue
            for id_entry in type_entry.directory.entries:
                for lang_entry in id_entry.directory.entries:
                    data_rva = lang_entry.data.struct.OffsetToData
                    size     = lang_entry.data.struct.Size
                    blob     = pe.get_data(data_rva, size)
                    if blob:
                        return blob
    except Exception:
        pass
    finally:
        try:
            pe.close()
        except Exception:
            pass
    return blob


def _read_sidecar_manifest(path: Path) -> Optional[bytes]:
    """Read a <binary>.manifest sidecar file if it exists."""
    sidecar = path.with_suffix(path.suffix + ".manifest")
    try:
        if sidecar.is_file():
            return sidecar.read_bytes()
    except (PermissionError, OSError):
        pass
    return None


# ── Public API ───────────────────────────────────────────────────────────────

@lru_cache(maxsize=4096)
def get_manifest(path: Path) -> ManifestInfo:
    """
    Parse the manifest for path. Returns an empty ManifestInfo
    (has_manifest=False) if no manifest is present or it fails to parse.

    Cached so the same component manifest isn't parsed repeatedly when
    multiple binaries in the same WinSxS folder share it.
    """
    blob = _read_embedded_manifest(path) or _read_sidecar_manifest(path)
    if not blob:
        return ManifestInfo()

    info = _parse_xml(blob)
    return info if info is not None else ManifestInfo(has_manifest=True)


def is_manifest_bound(path: Path, dll_name: str) -> bool:
    """
    Convenience: does the binary's manifest bind dll_name to a fixed location?
    A bound import cannot be hijacked via application-directory placement.
    """
    return get_manifest(path).binds(dll_name)
