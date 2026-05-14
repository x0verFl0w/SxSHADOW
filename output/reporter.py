"""
SxSHADOW — output.reporter
Rich console output, JSON serialisation, and self-contained HTML report.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core import HijackCandidate, ScanResult

# ── Banner ────────────────────────────────────────────────────────────────────

_BANNER = """\
[bold red]
  ███████╗██╗  ██╗███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
  ██╔════╝╚██╗██╔╝██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
  ███████╗ ╚███╔╝ ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
  ╚════██║ ██╔██╗ ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
  ███████║██╔╝ ██╗███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ [/bold red]
[dim]  Component Store Hijack Automated Discovery & Weaponization  v1.0[/dim]
[dim]  Authorized red team use only · WinSxS DLL side-loading forge[/dim]
"""


def print_banner(console: Console) -> None:
    console.print(_BANNER)


# ── Console results table ─────────────────────────────────────────────────────

def _score_color(score: int) -> str:
    if score >= 70: return "bright_green"
    if score >= 50: return "yellow"
    if score >= 30: return "orange3"
    return "red"


def _signed_markup(signed: Optional[bool]) -> str:
    if signed is True:  return "[bold green]YES[/bold green]"
    if signed is False: return "[red]NO[/red]"
    return "[dim]?[/dim]"


def print_results(result: ScanResult, console: Console, top_n: int = 20) -> None:
    """Print a ranked candidate table to the console."""
    shown = result.candidates[:top_n]
    if not shown:
        console.print("[yellow][!] No hijackable candidates found.[/yellow]")
        return

    tbl = Table(
        title=f"[bold]SxSHADOW — Top {len(shown)} Hijack Candidates[/bold]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
        expand=False,
    )
    tbl.add_column("#",           style="dim",        width=4,  justify="right")
    tbl.add_column("Score",       justify="right",     width=6)
    tbl.add_column("Trust/Ease/Impact", width=14)
    tbl.add_column("Host Binary", style="cyan bold",  min_width=18)
    tbl.add_column("Hijack DLL",  style="yellow",     min_width=18)
    tbl.add_column("Arch",        width=5)
    tbl.add_column("Signed",      width=7)
    tbl.add_column("Exports",     justify="right",    width=8)
    tbl.add_column("Version",     style="dim",        min_width=12)

    for i, c in enumerate(shown, 1):
        col  = _score_color(c.score)
        brk  = c.score_breakdown
        breakdown = (
            f"[dim]{brk.get('trust',0)}/"
            f"{brk.get('ease',0)}/"
            f"{brk.get('impact',0)}[/dim]"
        )
        tbl.add_row(
            str(i),
            f"[{col}]{c.score}[/{col}]",
            breakdown,
            c.binary_name,
            c.hijackable_dll,
            c.binary_arch,
            _signed_markup(c.binary_signed),
            str(len(c.real_dll_exports)),
            c.component_version,
        )

    console.print(tbl)
    console.print(
        f"\n[dim]  Scanned {result.total_binaries_examined:,} binaries · "
        f"Elapsed {result.scan_duration_seconds:.1f}s · "
        f"{len(result.candidates)} candidate(s) total[/dim]\n"
    )


def _defensive_color(priority: int) -> str:
    if priority >= 60: return "bright_red"
    if priority >= 40: return "orange3"
    if priority >= 20: return "yellow"
    return "green"


def print_candidate_detail(c: HijackCandidate, console: Console) -> None:
    """Print a full detail panel for one candidate."""
    col  = _score_color(c.score)
    brk  = c.score_breakdown
    dcol = _defensive_color(c.defensive_priority)
    dbrk = c.defensive_breakdown
    publisher = c.binary_publisher or "[dim](not collected)[/dim]"
    bin_hash  = c.binary_sha256 or "[dim](not collected)[/dim]"
    dll_hash  = c.real_dll_sha256 or "[dim](not collected)[/dim]"
    abused    = ("[bright_red]YES[/bright_red] — in hijacklibs corpus"
                 if c.known_abused else "[dim]no[/dim]")

    lines: List[str] = [
        f"[bold]Host binary :[/bold]  {c.binary_path}",
        f"[bold]Architecture:[/bold]  {c.binary_arch}",
        f"[bold]Signed      :[/bold]  {_signed_markup(c.binary_signed)}",
        f"[bold]Publisher   :[/bold]  {publisher}",
        f"[bold]Host SHA-256:[/bold]  {bin_hash}",
        f"[bold]Component   :[/bold]  {c.component_name}  ({c.component_version})",
        "",
        f"[bold]Hijack DLL  :[/bold]  [yellow]{c.hijackable_dll}[/yellow]",
        f"[bold]Real DLL    :[/bold]  {c.real_dll_path or '(not found on this system)'}",
        f"[bold]Real SHA-256:[/bold]  {dll_hash}",
        f"[bold]Delay-loaded:[/bold]  {c.delay_loaded}",
        f"[bold]Export count:[/bold]  {len(c.real_dll_exports)}",
        "",
        f"[bold]Score       :[/bold]  [{col}]{c.score}/100[/{col}]  "
        f"[dim](trust={brk.get('trust',0)} ease={brk.get('ease',0)} impact={brk.get('impact',0)})[/dim]",
        "",
        f"[bold]Staging path:[/bold]  {c.suggested_drop_path}",
        "",
        "[bold]Attack steps:[/bold]",
        f"  1. Compile proxy DLL  →  {c.hijackable_dll}",
        f"  2. Copy to staging    →  {c.suggested_drop_path}\\",
        f"  3. Copy host binary   →  {c.suggested_drop_path}\\{c.binary_name}",
        f"  4. Execute            →  {c.suggested_drop_path}\\{c.binary_name}",
        f"     The signed Microsoft binary loads your proxy {c.hijackable_dll}.",
        "",
        "[bold]Detection awareness:[/bold]",
        f"  Defensive priority  : [{dcol}]{c.defensive_priority}/100[/{dcol}] "
        f"[dim](known_abuse={dbrk.get('known_abuse',0)} stealth={dbrk.get('stealth',0)} "
        f"exposure={dbrk.get('exposure',0)})[/dim]",
        f"  Known-abused DLL    : {abused}",
    ]
    if c.known_abused:
        lines.append(
            "  [orange3]⚠ This DLL has prior side-load tradecraft on file. "
            "Vendor & Sigma rules likely cover it.[/orange3]"
        )

    if c.real_dll_exports:
        exp_names = [e.name or f"#ord{e.ordinal}" for e in c.real_dll_exports[:8]]
        suffix    = f" … +{len(c.real_dll_exports)-8} more" if len(c.real_dll_exports) > 8 else ""
        lines += ["", f"[bold]Exports (sample):[/bold]  {', '.join(exp_names)}{suffix}"]

    panel = Panel(
        "\n".join(lines),
        title=f"[bold {col}]Candidate Detail — {c.binary_name} / {c.hijackable_dll}[/bold {col}]",
        border_style=col,
        expand=False,
    )
    console.print(panel)


# ── JSON output ───────────────────────────────────────────────────────────────

def _candidate_to_dict(c: HijackCandidate) -> dict:
    return {
        "binary_path":       str(c.binary_path),
        "binary_name":       c.binary_name,
        "binary_arch":       c.binary_arch,
        "binary_signed":     c.binary_signed,
        "component_name":    c.component_name,
        "component_version": c.component_version,
        "hijackable_dll":    c.hijackable_dll,
        "real_dll_path":     str(c.real_dll_path) if c.real_dll_path else None,
        "export_count":      len(c.real_dll_exports),
        "delay_loaded":      c.delay_loaded,
        "score":             c.score,
        "score_breakdown":   c.score_breakdown,
        "suggested_drop_path": c.suggested_drop_path,
    }


def save_json(result: ScanResult, path: Path) -> None:
    """Serialise the full ScanResult to a JSON file."""
    data = {
        "tool":            "SxSHADOW",
        "version":         "1.0.0",
        "generated":       datetime.now().isoformat(),
        "winsxs_path":     str(result.winsxs_path),
        "binaries_scanned": result.total_binaries_examined,
        "duration_seconds": round(result.scan_duration_seconds, 2),
        "candidates":      [_candidate_to_dict(c) for c in result.candidates],
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ── HTML report ───────────────────────────────────────────────────────────────

def save_html(result: ScanResult, path: Path) -> None:
    """
    Write a self-contained HTML report with an inline sortable table.
    No external CDN dependencies — everything is inlined.
    """
    rows_html = []
    for i, c in enumerate(result.candidates, 1):
        signed_cell = (
            '<span class="yes">YES</span>' if c.binary_signed else
            '<span class="no">NO</span>'  if c.binary_signed is False else
            '<span class="unk">?</span>'
        )
        score_cls = (
            "score-hi" if c.score >= 70 else
            "score-md" if c.score >= 45 else "score-lo"
        )
        rows_html.append(
            f"<tr>"
            f"<td>{i}</td>"
            f'<td class="{score_cls}">{c.score}</td>'
            f"<td>{c.binary_name}</td>"
            f"<td>{c.hijackable_dll}</td>"
            f"<td>{c.binary_arch}</td>"
            f"<td>{signed_cell}</td>"
            f"<td>{len(c.real_dll_exports)}</td>"
            f"<td>{c.component_version}</td>"
            f"<td>{c.suggested_drop_path}</td>"
            f"</tr>"
        )

    ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html  = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SxSHADOW Report — {ts}</title>
<style>
  body{{font-family:monospace;background:#0d0d0d;color:#ccc;padding:2em}}
  h1{{color:#e05252}}h2{{color:#aaa;font-size:1em}}
  table{{border-collapse:collapse;width:100%}}
  th{{background:#1a1a2e;color:#8be;padding:8px;cursor:pointer;user-select:none}}
  td{{padding:6px 8px;border-bottom:1px solid #222}}
  tr:hover td{{background:#111}}
  .score-hi{{color:#4caf50;font-weight:bold}}
  .score-md{{color:#ff9800;font-weight:bold}}
  .score-lo{{color:#f44336}}
  .yes{{color:#4caf50}}.no{{color:#f44336}}.unk{{color:#888}}
  #search{{background:#111;border:1px solid #333;color:#ccc;padding:6px;margin:1em 0;width:300px}}
</style>
</head>
<body>
<h1>SxSHADOW</h1>
<h2>Component Store Hijack Report · {ts}</h2>
<p>Binaries scanned: <b>{result.total_binaries_examined:,}</b> &nbsp;|&nbsp;
   Duration: <b>{result.scan_duration_seconds:.1f}s</b> &nbsp;|&nbsp;
   Candidates: <b>{len(result.candidates)}</b></p>
<input id="search" type="text" placeholder="Filter...">
<table id="tbl">
<thead><tr>
  <th onclick="sortCol(0)">#</th>
  <th onclick="sortCol(1)">Score ▾</th>
  <th onclick="sortCol(2)">Host Binary</th>
  <th onclick="sortCol(3)">Hijack DLL</th>
  <th onclick="sortCol(4)">Arch</th>
  <th onclick="sortCol(5)">Signed</th>
  <th onclick="sortCol(6)">Exports</th>
  <th onclick="sortCol(7)">Version</th>
  <th onclick="sortCol(8)">Staging Path</th>
</tr></thead>
<tbody>{''.join(rows_html)}</tbody>
</table>
<script>
let asc=true,lastCol=-1;
function sortCol(c){{
  const tb=document.querySelector('#tbl tbody');
  const rows=[...tb.rows];
  asc=(c===lastCol)?!asc:false; lastCol=c;
  rows.sort((a,b)=>{{
    const v=x=>a.cells[c].textContent,w=x=>b.cells[c].textContent;
    const na=parseFloat(v()),nb=parseFloat(w());
    if(!isNaN(na)&&!isNaN(nb)) return asc?na-nb:nb-na;
    return asc?v().localeCompare(w()):w().localeCompare(v());
  }});
  rows.forEach(r=>tb.appendChild(r));
}}
document.getElementById('search').addEventListener('input',function(){{
  const q=this.value.toLowerCase();
  document.querySelectorAll('#tbl tbody tr').forEach(r=>
    r.style.display=r.textContent.toLowerCase().includes(q)?'':'none');
}});
</script>
</body></html>"""
    path.write_text(html, encoding="utf-8")
