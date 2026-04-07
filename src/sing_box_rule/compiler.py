from __future__ import annotations

import subprocess
from pathlib import Path


def compile_srs(json_path: Path, srs_path: Path) -> None:
    command = [
        "sing-box",
        "rule-set",
        "compile",
        "--output",
        str(srs_path),
        str(json_path),
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "sing-box rule-set compile failed")
