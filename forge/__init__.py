"""WRAITH forge public API."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List


@dataclass
class ProxyBundle:
    """All generated artefacts for one proxy DLL."""
    candidate_binary: str       # host EXE name
    target_dll: str             # the DLL we are replacing
    c_source: str               # rendered proxy_dll.c content
    def_source: str             # rendered .def file content
    build_bat: str              # Windows build script
    build_sh: str               # Linux cross-compile script
    output_dir: Path = Path(".")

    def write(self) -> List[Path]:
        """Write all artefacts to output_dir. Returns list of written paths."""
        written: List[Path] = []
        self.output_dir.mkdir(parents=True, exist_ok=True)

        dll_stem = Path(self.target_dll).stem
        files = {
            f"{dll_stem}_proxy.c": self.c_source,
            f"{dll_stem}.def": self.def_source,
            "build.bat": self.build_bat,
            "build.sh": self.build_sh,
        }
        for fname, content in files.items():
            p = self.output_dir / fname
            p.write_text(content, encoding="utf-8")
            written.append(p)
        return written


__all__ = ["ProxyBundle"]
