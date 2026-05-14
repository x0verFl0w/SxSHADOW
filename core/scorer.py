"""
WRAITH — core.scorer
Scores and ranks HijackCandidate objects on a 0-100 scale.

Score breakdown (sums to 100):
  trust   0-30  — how trusted/signed is the host binary
  ease    0-30  — how easy to build a working proxy (fewer exports = easier)
  impact  0-40  — expected operational impact

Higher score = better candidate.
"""
from __future__ import annotations

from typing import List

from core import HijackCandidate

# Real-world side-load binaries observed in APT and red team tradecraft
_HIGH_VALUE_BINARIES = frozenset({
    "ngentask.exe", "mscorsvw.exe", "ngen.exe",
    "msiexec.exe", "regsvr32.exe", "rundll32.exe",
    "msbuild.exe", "csc.exe", "vbc.exe", "jsc.exe",
    "installutil.exe", "ieexec.exe",
    "wscript.exe", "cscript.exe",
    "aspnet_compiler.exe", "aspnet_state.exe",
    "appidpolicyconverter.exe", "bginfo.exe",
    "dfshim.dll",   # ClickOnce launcher
})


# ── trust (0-30) ─────────────────────────────────────────────────────────────

def _score_trust(c: HijackCandidate) -> int:
    """
    Reward Microsoft-signed and well-known binaries.
    A signed host binary provides maximum trust transfer: Defender sees a
    known-good process; the injected DLL rides that reputation.
    """
    s = 0
    if c.binary_signed is True:
        s += 20
    if c.binary_name.lower() in _HIGH_VALUE_BINARIES:
        s += 10
    elif c.binary_name.lower().endswith(".exe"):
        s += 3   # Any EXE is better than a DLL as host
    return min(s, 30)


# ── ease (0-30) ───────────────────────────────────────────────────────────────

def _score_ease(c: HijackCandidate) -> int:
    """
    Fewer exports on the real DLL means a simpler, more reliable proxy.
    A DLL with 200 exports means 200 forwarding stubs to generate; one with
    3 exports is trivially proxied.
    """
    n = len(c.real_dll_exports)
    if n == 0:   return 30    # No exports → trivial; DLL loaded for side-effect
    if n <= 5:   return 27
    if n <= 15:  return 22
    if n <= 30:  return 15
    if n <= 60:  return 8
    if n <= 100: return 3
    return 0


# ── impact (0-40) ────────────────────────────────────────────────────────────

def _score_impact(c: HijackCandidate) -> int:
    """
    Quality of the trust transfer and reliability of execution timing.

    +20  binary is signed  → our DLL runs inside a signed/trusted process
    +10  real DLL found    → proxy will forward correctly; app stays functional
    +10  not delay-loaded  → fires at DLL_PROCESS_ATTACH, not on first call
    """
    s = 0
    if c.binary_signed is True:
        s += 20
    if c.real_dll_path is not None:
        s += 10
    if not c.delay_loaded:
        s += 10
    return min(s, 40)


# ── public API ────────────────────────────────────────────────────────────────

def score(c: HijackCandidate) -> int:
    """
    Compute the composite 0-100 score for c, storing the result in
    c.score and c.score_breakdown.  Returns the computed score.
    """
    t = _score_trust(c)
    e = _score_ease(c)
    i = _score_impact(c)
    total = t + e + i
    c.score = total
    c.score_breakdown = {"trust": t, "ease": e, "impact": i}
    return total


def rank(candidates: List[HijackCandidate]) -> List[HijackCandidate]:
    """
    Score every candidate and return the list sorted descending by score.
    Mutates each candidate's .score and .score_breakdown in place.
    """
    for c in candidates:
        score(c)
    return sorted(candidates, key=lambda c: c.score, reverse=True)


# ── Defensive priority score (separate axis from offensive composite) ────────
#
# Where score()/rank() answer "how attractive is this to an attacker?", the
# defensive priority answers "how worth a SOC's attention is this?".
#
# Components (sum to 100):
#   known-abuse    0-40  — DLL appears in hijacklibs.net (prior art exists)
#   stealth        0-30  — would the load evade naive EDR? (delay-load,
#                          host is a signed Microsoft binary that LOLBins use)
#   exposure       0-30  — load reliability & blast radius proxies

_LOLBIN_BINARIES = frozenset({
    "rundll32.exe", "regsvr32.exe", "msiexec.exe", "msbuild.exe",
    "installutil.exe", "ieexec.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "presentationhost.exe", "regsvcs.exe", "regasm.exe",
    "aspnet_compiler.exe", "aspnet_state.exe", "csc.exe", "vbc.exe",
    "ngentask.exe", "mscorsvw.exe", "ngen.exe",
})


def _score_def_known_abuse(c: HijackCandidate) -> int:
    return 40 if c.known_abused else 0


def _score_def_stealth(c: HijackCandidate) -> int:
    s = 0
    # Signed Microsoft host = the load won't look anomalous to image-load
    # heuristics; defenders need an explicit detection.
    if c.binary_signed is True:
        s += 15
    # Delay-loaded imports fire only when the function is first called,
    # which is harder to correlate with process start.
    if c.delay_loaded:
        s += 10
    # LOLBin hosts are noisier baselines; an additional detection helps.
    if c.binary_name.lower() in _LOLBIN_BINARIES:
        s += 5
    return min(s, 30)


def _score_def_exposure(c: HijackCandidate) -> int:
    s = 0
    # Real DLL present on this system → realistic exploitation path.
    if c.real_dll_path is not None:
        s += 15
    # Fewer exports = trivial proxy = lower bar = higher likelihood.
    n = len(c.real_dll_exports)
    if   n == 0:  s += 15
    elif n <= 5:  s += 12
    elif n <= 15: s += 9
    elif n <= 30: s += 6
    elif n <= 60: s += 3
    return min(s, 30)


def score_defensive(c: HijackCandidate) -> int:
    """
    Compute the 0-100 defensive priority score for c.
    Stored in c.defensive_priority and c.defensive_breakdown.
    Higher = more worth a detection rule.
    """
    ka = _score_def_known_abuse(c)
    st = _score_def_stealth(c)
    ex = _score_def_exposure(c)
    total = ka + st + ex
    c.defensive_priority = total
    c.defensive_breakdown = {"known_abuse": ka, "stealth": st, "exposure": ex}
    return total
