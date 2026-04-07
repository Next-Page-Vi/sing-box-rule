from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

from .asn import ASNLookupError, ASNPrefixResolver
from .clash import ParseResult, build_ruleset, parse_clash_list_file, ruleset_to_json
from .compiler import compile_srs
from .config import load_config
from .discovery import discover_rule_files
from .git_source import clone_repository
from .models import BuildConfig, BuildReport, CompiledArtifact, SourceFile


def build_from_config(config_path: Path) -> BuildReport:
    config = load_config(config_path)
    output_root = config.output.directory
    _prepare_output_directory(output_root)

    report = BuildReport(
        source_repo_url=config.source.repo_url,
        source_branch=config.source.branch,
        source_path=config.source.path,
        output_directory=str(output_root),
        generated_at=datetime.now(UTC).isoformat(),
    )

    try:
        with clone_repository(
            config.source.repo_url,
            config.source.branch,
            config.source.path,
        ) as repo_root:
            list_files, markdown_files = discover_rule_files(repo_root, config.source.path)
            _copy_markdown_files(markdown_files, output_root, report)
            _build_rule_files(list_files, output_root, report, config)
    except Exception as exc:
        report.add_error(str(exc), "build")
    finally:
        _write_manifest(output_root / config.output.manifest, report)

    return report


def _prepare_output_directory(output_root: Path) -> None:
    shutil.rmtree(output_root, ignore_errors=True)
    output_root.mkdir(parents=True, exist_ok=True)


def _copy_markdown_files(
    markdown_files: list[SourceFile],
    output_root: Path,
    report: BuildReport,
) -> None:
    for source_file in markdown_files:
        destination = output_root / source_file.relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_file.absolute_path, destination)
        report.copied_markdown.append(
            CompiledArtifact(source=str(source_file.relative_path), copied_path=str(destination))
        )


def _build_rule_files(
    list_files: list[SourceFile],
    output_root: Path,
    report: BuildReport,
    config: BuildConfig,
) -> None:
    parsed_results: list[tuple[SourceFile, ParseResult]] = []
    unique_asns: set[str] = set()

    for source_file in list_files:
        try:
            parse_result = parse_clash_list_file(
                source_file.absolute_path,
                keep_ambiguous_process_name=config.conversion.keep_ambiguous_process_name,
            )
            report.diagnostics.extend(parse_result.diagnostics)
            unique_asns.update(parse_result.ip_asn_refs)
            parsed_results.append((source_file, parse_result))
        except Exception as exc:
            report.add_error(str(exc), str(source_file.relative_path))

    resolved_asns = _resolve_asn_prefixes(unique_asns, report, config)

    for source_file, parse_result in parsed_results:
        try:
            file_asn_prefixes = _collect_file_asn_prefixes(
                ip_asn_refs=parse_result.ip_asn_refs,
                resolved_asns=resolved_asns,
                report=report,
                config=config,
            )
            ruleset = build_ruleset(parse_result, asn_prefixes=file_asn_prefixes)

            target_base = output_root / source_file.relative_parent / source_file.stem
            target_base.parent.mkdir(parents=True, exist_ok=True)

            json_path = target_base.with_suffix(".json")
            json_path.write_text(ruleset_to_json(ruleset), encoding="utf-8")

            srs_path: Path | None = None
            if config.output.compile_srs:
                srs_path = target_base.with_suffix(".srs")
                compile_srs(json_path, srs_path)
            if not config.output.keep_json and json_path.exists():
                json_path.unlink()
                json_path = None

            report.converted.append(
                CompiledArtifact(
                    source=str(source_file.relative_path),
                    json_path=str(json_path) if json_path is not None else None,
                    srs_path=str(srs_path) if srs_path is not None else None,
                )
            )
        except Exception as exc:
            report.add_error(str(exc), str(source_file.relative_path))


def _resolve_asn_prefixes(
    unique_asns: set[str],
    report: BuildReport,
    config: BuildConfig,
) -> dict[str, list[str]]:
    if not config.conversion.expand_ip_asn or not unique_asns:
        return {}

    resolver = ASNPrefixResolver(
        source=config.conversion.asn_source,
        timeout_seconds=config.conversion.asn_request_timeout_seconds,
    )
    resolved: dict[str, list[str]] = {}
    for asn in sorted(unique_asns, key=lambda value: int(value)):
        try:
            resolved[asn] = resolver.resolve(asn)
        except ASNLookupError as exc:
            if config.conversion.fail_on_asn_lookup_error:
                raise RuntimeError(str(exc)) from exc
            report.add_warning(f"IP-ASN lookup failed: {exc}", f"AS{asn}")
    return resolved


def _collect_file_asn_prefixes(
    *,
    ip_asn_refs: dict[str, list[str]],
    resolved_asns: dict[str, list[str]],
    report: BuildReport,
    config: BuildConfig,
) -> dict[str, list[str]]:
    file_asn_prefixes: dict[str, list[str]] = {}
    for asn, sources in ip_asn_refs.items():
        prefixes = resolved_asns.get(asn)
        if prefixes is None:
            message = (
                "unsupported or malformed rule, skipped"
                if not config.conversion.expand_ip_asn
                else "IP-ASN expansion unavailable, skipped"
            )
            for source in sources:
                report.add_warning(message, source)
            continue
        file_asn_prefixes[asn] = prefixes
    return file_asn_prefixes


def _write_manifest(manifest_path: Path, report: BuildReport) -> None:
    payload = {
        "source_repo_url": report.source_repo_url,
        "source_branch": report.source_branch,
        "source_path": report.source_path,
        "output_directory": report.output_directory,
        "generated_at": report.generated_at,
        "converted": [
            {
                "source": item.source,
                "json_path": item.json_path,
                "srs_path": item.srs_path,
                "copied_path": item.copied_path,
            }
            for item in report.converted
        ],
        "copied_markdown": [
            {
                "source": item.source,
                "json_path": item.json_path,
                "srs_path": item.srs_path,
                "copied_path": item.copied_path,
            }
            for item in report.copied_markdown
        ],
        "diagnostics": [
            {
                "severity": item.severity,
                "message": item.message,
                "source": item.source,
            }
            for item in report.diagnostics
        ],
    }
    manifest_content = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    manifest_path.write_text(manifest_content, encoding="utf-8")
