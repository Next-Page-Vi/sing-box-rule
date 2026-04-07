from __future__ import annotations

import tomllib
from pathlib import Path
from typing import cast

from .models import BuildConfig, ConversionConfig, OutputConfig, SourceConfig


def load_config(config_path: Path) -> BuildConfig:
    with config_path.open("rb") as file:
        raw_data = tomllib.load(file)

    source_table = _require_table(raw_data, "source")
    output_table = _require_table(raw_data, "output")
    conversion_table = _require_table(raw_data, "conversion")

    source = SourceConfig(
        repo_url=_require_non_empty_string(source_table, "repo_url"),
        branch=_require_non_empty_string(source_table, "branch"),
        path=_normalize_repo_path(_require_non_empty_string(source_table, "path")),
    )
    output = OutputConfig(
        directory=Path(_require_non_empty_string(output_table, "directory")),
        keep_json=_require_bool(output_table, "keep_json"),
        compile_srs=_require_bool(output_table, "compile_srs"),
        manifest=_require_non_empty_string(output_table, "manifest"),
    )
    conversion = ConversionConfig(
        keep_ambiguous_process_name=_require_bool(
            conversion_table,
            "keep_ambiguous_process_name",
        ),
        expand_ip_asn=_require_bool(conversion_table, "expand_ip_asn"),
        asn_source=_require_non_empty_string(conversion_table, "asn_source"),
        asn_request_timeout_seconds=_require_positive_int(
            conversion_table,
            "asn_request_timeout_seconds",
        ),
        fail_on_asn_lookup_error=_require_bool(
            conversion_table,
            "fail_on_asn_lookup_error",
        ),
    )
    return BuildConfig(source=source, output=output, conversion=conversion)


def _require_table(raw_data: object, key: str) -> dict[str, object]:
    if not isinstance(raw_data, dict):
        raise ValueError("configuration root must be a table")
    typed_data = cast(dict[str, object], raw_data)
    value = typed_data.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"missing or invalid [{key}] table")
    return cast(dict[str, object], value)


def _require_non_empty_string(table: dict[str, object], key: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing or invalid string value for {key}")
    return value.strip()


def _require_bool(table: dict[str, object], key: str) -> bool:
    value = table.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"missing or invalid boolean value for {key}")
    return value


def _require_positive_int(table: dict[str, object], key: str) -> int:
    value = table.get(key)
    if not isinstance(value, int) or value <= 0:
        raise ValueError(f"missing or invalid positive integer value for {key}")
    return value


def _normalize_repo_path(value: str) -> str:
    normalized = value.strip().strip("/")
    if not normalized:
        raise ValueError("source.path must not be empty")
    return normalized
