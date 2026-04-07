from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

RuleSeverity = Literal["warning", "error"]


@dataclass(frozen=True)
class SourceConfig:
    repo_url: str
    branch: str
    path: str


@dataclass(frozen=True)
class OutputConfig:
    directory: Path
    keep_json: bool
    compile_srs: bool
    manifest: str


@dataclass(frozen=True)
class ConversionConfig:
    keep_ambiguous_process_name: bool
    expand_ip_asn: bool
    asn_source: str
    asn_request_timeout_seconds: int
    fail_on_asn_lookup_error: bool


@dataclass(frozen=True)
class BuildConfig:
    source: SourceConfig
    output: OutputConfig
    conversion: ConversionConfig


@dataclass(frozen=True)
class SourceFile:
    source_root: Path
    absolute_path: Path
    relative_path: Path

    @property
    def stem(self) -> str:
        return self.absolute_path.stem

    @property
    def relative_parent(self) -> Path:
        return self.relative_path.parent


@dataclass(frozen=True)
class RuleDiagnostic:
    severity: RuleSeverity
    message: str
    source: str


@dataclass(frozen=True)
class CompiledArtifact:
    source: str
    json_path: str | None = None
    srs_path: str | None = None
    copied_path: str | None = None


@dataclass
class BuildReport:
    source_repo_url: str
    source_branch: str
    source_path: str
    output_directory: str
    generated_at: str
    converted: list[CompiledArtifact] = field(default_factory=list)
    copied_markdown: list[CompiledArtifact] = field(default_factory=list)
    diagnostics: list[RuleDiagnostic] = field(default_factory=list)

    def add_error(self, message: str, source: str) -> None:
        self.diagnostics.append(RuleDiagnostic(severity="error", message=message, source=source))

    def add_warning(self, message: str, source: str) -> None:
        self.diagnostics.append(RuleDiagnostic(severity="warning", message=message, source=source))

    @property
    def has_errors(self) -> bool:
        return any(item.severity == "error" for item in self.diagnostics)
