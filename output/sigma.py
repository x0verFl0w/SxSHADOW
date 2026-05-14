"""
output.sigma
Emit Sigma detection rules for ranked hijack candidates.

Two rule shapes per high-priority candidate:

  1. image_load:
       - host binary loads the target DLL
       - AND ImageLoaded path is NOT under C:\\Windows\\WinSxS, System32,
         or SysWOW64 (the only places the legitimate DLL should live)
     → fires when an attacker drops a proxy DLL next to a copy of the
       Microsoft-signed host binary in a writable directory.

  2. process_create:
       - host binary is observed running from a path outside
         C:\\Windows\\WinSxS\\... (the legit binary should only ever
         execute from its component folder).
     → catches the staging step before the DLL even loads.

Output is a single YAML document with multiple "---" separated rules,
ingestible by sigmac / pySigma.
"""
from __future__ import annotations

import hashlib
import re
from datetime import date
from pathlib import Path
from typing import Iterable, List

from core import HijackCandidate

# Defensive-priority threshold below which we don't emit a rule (noise).
_MIN_PRIORITY = 30


def _slug(s: str) -> str:
    """Filesystem-safe slug for rule names."""
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def _rule_uuid(binary: str, dll: str, kind: str) -> str:
    """Deterministic UUID-shaped string so re-runs don't churn rule IDs."""
    h = hashlib.sha1(f"sxshadow|{kind}|{binary}|{dll}".encode()).hexdigest()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _image_load_rule(c: HijackCandidate) -> str:
    rule_id = _rule_uuid(c.binary_name, c.hijackable_dll, "imageload")
    title = (f"DLL Side-Load via WinSxS Host {c.binary_name} → "
             f"{c.hijackable_dll}")
    return f"""title: {title}
id: {rule_id}
status: experimental
description: |
  Detects an instance of the Microsoft-signed WinSxS host '{c.binary_name}'
  loading '{c.hijackable_dll}' from a path outside of the expected system
  directories. WinSxS components legitimately load their imports from
  C:\\Windows\\WinSxS or C:\\Windows\\System32 (or SysWOW64 for 32-bit
  hosts); a load from any other directory is a strong side-loading
  indicator (MITRE T1574.002).
references:
  - https://attack.mitre.org/techniques/T1574/002/
  - https://hijacklibs.net/
tags:
  - attack.defense_evasion
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1574.002
author: SxSHADOW (generated)
date: {date.today().isoformat()}
logsource:
  category: image_load
  product: windows
detection:
  selection_host:
    Image|endswith: '\\{c.binary_name}'
  selection_dll:
    ImageLoaded|endswith: '\\{c.hijackable_dll}'
  filter_legit_paths:
    ImageLoaded|startswith:
      - 'C:\\Windows\\WinSxS\\'
      - 'C:\\Windows\\System32\\'
      - 'C:\\Windows\\SysWOW64\\'
  condition: selection_host and selection_dll and not filter_legit_paths
falsepositives:
  - Legitimate redistribution of the host binary in a non-standard install
    path that ships its own private copy of the DLL.
level: high
"""


def _process_create_rule(c: HijackCandidate) -> str:
    rule_id = _rule_uuid(c.binary_name, c.hijackable_dll, "proccreate")
    title = f"WinSxS Host {c.binary_name} Executed Outside Component Store"
    return f"""title: {title}
id: {rule_id}
status: experimental
description: |
  The Microsoft-signed binary '{c.binary_name}' shipped only inside the
  WinSxS component store. Execution from any other path strongly suggests
  it has been copied into a writable directory as a staging step for DLL
  side-loading of '{c.hijackable_dll}' (MITRE T1574.002).
references:
  - https://attack.mitre.org/techniques/T1574/002/
tags:
  - attack.defense_evasion
  - attack.persistence
  - attack.t1574.002
author: SxSHADOW (generated)
date: {date.today().isoformat()}
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\{c.binary_name}'
  filter_legit_path:
    Image|startswith: 'C:\\Windows\\WinSxS\\'
  condition: selection and not filter_legit_path
falsepositives:
  - Legitimate redistribution of the host binary by an MSI installer.
level: medium
"""


def emit_sigma(
    candidates: Iterable[HijackCandidate],
    out_path: Path,
    min_priority: int = _MIN_PRIORITY,
    max_rules: int = 200,
) -> int:
    """
    Write a multi-document YAML file with Sigma rules for every candidate
    with defensive_priority >= min_priority. Returns the rule count written.
    """
    seen: set = set()
    docs: List[str] = []
    for c in candidates:
        if c.defensive_priority < min_priority:
            continue
        key = (c.binary_name.lower(), c.hijackable_dll.lower())
        if key in seen:
            continue
        seen.add(key)
        docs.append(_image_load_rule(c))
        docs.append(_process_create_rule(c))
        if len(docs) // 2 >= max_rules:
            break

    out_path.write_text("---\n" + "\n---\n".join(docs), encoding="utf-8")
    return len(docs)
