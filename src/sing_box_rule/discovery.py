from __future__ import annotations

from pathlib import Path

from .models import SourceFile

MARKDOWN_SUFFIXES = {".md", ".markdown"}


def discover_rule_files(
    repo_root: Path, source_path: str
) -> tuple[list[SourceFile], list[SourceFile]]:
    source_root = repo_root / source_path
    if not source_root.exists():
        raise FileNotFoundError(f"configured source path does not exist: {source_path}")
    if not source_root.is_dir():
        raise NotADirectoryError(f"configured source path is not a directory: {source_path}")

    list_files: list[SourceFile] = []
    markdown_files: list[SourceFile] = []

    for candidate in sorted(source_root.rglob("*")):
        if not candidate.is_file():
            continue
        relative_path = candidate.relative_to(source_root)
        source_file = SourceFile(
            source_root=source_root,
            absolute_path=candidate,
            relative_path=relative_path,
        )
        if candidate.suffix == ".list":
            list_files.append(source_file)
        elif candidate.suffix.lower() in MARKDOWN_SUFFIXES:
            markdown_files.append(source_file)

    return list_files, markdown_files
