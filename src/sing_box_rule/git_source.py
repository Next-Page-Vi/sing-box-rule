from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def clone_repository(repo_url: str, branch: str, source_path: str) -> Iterator[Path]:
    temp_dir = Path(tempfile.mkdtemp(prefix="sing-box-rule-"))
    clone_dir = temp_dir / "repo"
    try:
        _run_git_clone(
            repo_url=repo_url,
            branch=branch,
            destination=clone_dir,
            source_path=source_path,
        )
        yield clone_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _run_git_clone(repo_url: str, branch: str, destination: Path, source_path: str) -> None:
    clone_command = [
        "git",
        "clone",
        "--depth",
        "1",
        "--branch",
        branch,
        "--filter=blob:none",
        "--sparse",
        repo_url,
        str(destination),
    ]
    _run_git_command(clone_command)

    sparse_command = [
        "git",
        "-C",
        str(destination),
        "sparse-checkout",
        "set",
        "--no-cone",
        source_path,
    ]
    _run_git_command(sparse_command)


def _run_git_command(command: list[str]) -> None:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git command failed")
