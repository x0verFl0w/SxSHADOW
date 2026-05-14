"""
core.hijacklibs
Local-only lookup of DLL names that have been observed abused for
side-loading in the wild.

Source: distilled from https://hijacklibs.net/ (community-maintained,
CC-BY-4.0). We ship a static name list — no network calls at scan time.
Defenders should periodically refresh this list from upstream.

The list intentionally contains only DLL *names*, not full IOCs: the
scanner already provides the binary/path context, and the role of this
module is to tell the scorer "this DLL has prior art for abuse — bump
its detection priority."
"""
from __future__ import annotations

from functools import lru_cache
from typing import FrozenSet

# Curated subset of hijacklibs.net — DLL names observed abused in real
# campaigns. Keep all lowercase. This is a starter list; defenders should
# periodically sync the full corpus.
_KNOWN_ABUSED: FrozenSet[str] = frozenset({
    # Microsoft-shipped DLLs frequently abused via side-loading
    "version.dll",
    "dbghelp.dll",
    "dbgcore.dll",
    "winmm.dll",
    "winhttp.dll",
    "wlanapi.dll",
    "wlbsctrl.dll",
    "wer.dll",
    "wtsapi32.dll",
    "userenv.dll",
    "secur32.dll",
    "schannel.dll",
    "cryptbase.dll",
    "cryptsp.dll",
    "rasapi32.dll",
    "rasman.dll",
    "rasadhlp.dll",
    "msvcr100.dll",
    "msvcr110.dll",
    "msvcr120.dll",
    "mscoree.dll",
    "mscorsvc.dll",
    "mfplat.dll",
    "msi.dll",
    "msimg32.dll",
    "msasn1.dll",
    "iphlpapi.dll",
    "netapi32.dll",
    "ntmarta.dll",
    "propsys.dll",
    "profapi.dll",
    "sspicli.dll",
    "shfolder.dll",
    "uxtheme.dll",
    "vssapi.dll",
    "wevtapi.dll",
    "winsta.dll",
    "wkscli.dll",
    "wldap32.dll",
    "dwmapi.dll",
    "dnsapi.dll",
    "edputil.dll",
    "elscore.dll",
    "fwbase.dll",
    "linkinfo.dll",
    "loadperf.dll",
    "mfc42.dll",
    "ncrypt.dll",
    "ntshrui.dll",
    "oleacc.dll",
    "policymanager.dll",
    "rstrtmgr.dll",
    "samlib.dll",
    "srvcli.dll",
    "textinputframework.dll",
    "tiptsf.dll",
    "twinapi.dll",
    "wbemcomn.dll",
    "wininet.dll",
    "winnsi.dll",
})


@lru_cache(maxsize=4096)
def is_known_abused(dll_name: str) -> bool:
    """True if dll_name appears in the known-abused list."""
    return dll_name.lower() in _KNOWN_ABUSED


def known_abused_set() -> FrozenSet[str]:
    """Expose the underlying set (read-only) for reporters."""
    return _KNOWN_ABUSED
