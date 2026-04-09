from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from .models import RuleDiagnostic

MAP_DICT: dict[str, str] = {
    "DOMAIN-SUFFIX": "domain_suffix",
    "HOST-SUFFIX": "domain_suffix",
    "host-suffix": "domain_suffix",
    "DOMAIN": "domain",
    "HOST": "domain",
    "host": "domain",
    "DOMAIN-KEYWORD": "domain_keyword",
    "HOST-KEYWORD": "domain_keyword",
    "host-keyword": "domain_keyword",
    "IP-CIDR": "ip_cidr",
    "ip-cidr": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
    "IP6-CIDR": "ip_cidr",
    "SRC-IP-CIDR": "source_ip_cidr",
    "GEOIP": "geoip",
    "DST-PORT": "port",
    "SRC-PORT": "source_port",
    "URL-REGEX": "domain_regex",
    "DOMAIN-REGEX": "domain_regex",
}


@dataclass(frozen=True)
class ParseResult:
    grouped_rules: dict[str, set[str]]
    logical_rules: list[dict[str, object]]
    ip_asn_refs: dict[str, list[str]]
    diagnostics: list[RuleDiagnostic] = field(default_factory=list)


@dataclass(frozen=True)
class ProcessNameParseResult:
    grouped_entry: tuple[str, str] | None = None
    logical_rule: dict[str, object] | None = None
    diagnostic: str | None = None


def parse_clash_list_file(path: Path, *, keep_ambiguous_process_name: bool) -> ParseResult:
    grouped_rules: dict[str, set[str]] = defaultdict(set)
    logical_rules: list[dict[str, object]] = []
    ip_asn_refs: dict[str, list[str]] = defaultdict(list)
    diagnostics: list[RuleDiagnostic] = []

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        candidate = _strip_inline_comment(stripped)
        if not candidate:
            continue

        if candidate.startswith("AND,"):
            parsed_rule = _parse_logical_and_rule(candidate)
            if parsed_rule is None:
                diagnostics.append(
                    RuleDiagnostic(
                        severity="warning",
                        source=f"{path}:{line_number}",
                        message="unable to parse logical AND rule, skipped",
                    )
                )
                continue
            logical_rules.append(parsed_rule)
            continue

        process_rule = _parse_process_name_rule(
            candidate,
            keep_ambiguous_process_name=keep_ambiguous_process_name,
        )
        if process_rule is not None:
            if process_rule.grouped_entry is not None:
                rule_type, value = process_rule.grouped_entry
                grouped_rules[rule_type].add(value)
            if process_rule.logical_rule is not None:
                logical_rules.append(process_rule.logical_rule)
            if process_rule.diagnostic is not None:
                diagnostics.append(
                    RuleDiagnostic(
                        severity="warning",
                        source=f"{path}:{line_number}",
                        message=process_rule.diagnostic,
                    )
                )
            continue

        ip_asn = _parse_ip_asn_rule(candidate)
        if ip_asn is not None:
            ip_asn_refs[ip_asn].append(f"{path}:{line_number}")
            continue

        entry = _parse_standard_rule(candidate)
        if entry is None:
            diagnostics.append(
                RuleDiagnostic(
                    severity="warning",
                    source=f"{path}:{line_number}",
                    message="unsupported or malformed rule, skipped",
                )
            )
            continue

        rule_type, value = entry
        grouped_rules[rule_type].add(value)

    return ParseResult(
        grouped_rules=grouped_rules,
        logical_rules=_sort_logical_rules(logical_rules),
        ip_asn_refs=dict(ip_asn_refs),
        diagnostics=diagnostics,
    )


def build_ruleset(
    parsed: ParseResult,
    *,
    asn_prefixes: dict[str, list[str]] | None = None,
) -> dict[str, object]:
    grouped_rules = {rule_type: set(values) for rule_type, values in parsed.grouped_rules.items()}
    if asn_prefixes is not None:
        ip_cidr_values = grouped_rules.setdefault("ip_cidr", set())
        for prefixes in asn_prefixes.values():
            ip_cidr_values.update(prefixes)

    grouped_rules = {
        rule_type: values for rule_type, values in grouped_rules.items() if values
    }

    rules: list[dict[str, object]] = []
    if "domain" in grouped_rules:
        rules.append({"domain": sorted(grouped_rules.pop("domain"))})

    for rule_type in sorted(grouped_rules):
        rules.append({rule_type: sorted(grouped_rules[rule_type])})

    if parsed.logical_rules:
        rules.extend(parsed.logical_rules)

    ruleset = {"version": 2, "rules": rules}
    sorted_ruleset = _sort_nested_dict(ruleset)
    return cast(dict[str, object], sorted_ruleset)


def ruleset_to_json(ruleset: dict[str, object]) -> str:
    return json.dumps(ruleset, ensure_ascii=False, indent=2) + "\n"


def _parse_standard_rule(line: str) -> tuple[str, str] | None:
    parts = [part.strip() for part in line.split(",")]
    if len(parts) < 2:
        return _infer_rule_from_single_token(line)

    pattern = parts[0]
    address = parts[1]
    mapped = MAP_DICT.get(pattern)
    if mapped is None:
        return None

    cleaned_address = address.strip().strip("'").strip('"')
    if not cleaned_address:
        return None
    return mapped, cleaned_address


def _parse_ip_asn_rule(line: str) -> str | None:
    parts = [part.strip() for part in line.split(",")]
    if len(parts) < 2 or parts[0] != "IP-ASN":
        return None

    value = parts[1].strip().strip("'").strip('"')
    if not value or not value.isdigit():
        return None
    return value


def _parse_process_name_rule(
    line: str,
    *,
    keep_ambiguous_process_name: bool,
) -> ProcessNameParseResult | None:
    parts = [part.strip() for part in line.split(",")]
    if len(parts) < 2 or parts[0] != "PROCESS-NAME":
        return None

    value = parts[1].strip().strip("'").strip('"')
    if not value:
        return None

    if _looks_like_android_package_name(value):
        return ProcessNameParseResult(grouped_entry=("package_name", value))

    if _looks_like_process_name(value):
        return ProcessNameParseResult(grouped_entry=("process_name", value))

    if keep_ambiguous_process_name:
        return ProcessNameParseResult(
            logical_rule={
                "type": "logical",
                "mode": "or",
                "rules": [
                    {"package_name": [value]},
                    {"process_name": [value]},
                ],
            },
            diagnostic="ambiguous PROCESS-NAME preserved as logical or(process_name, package_name)",
        )

    return ProcessNameParseResult(diagnostic="ambiguous PROCESS-NAME skipped")


def _infer_rule_from_single_token(token: str) -> tuple[str, str] | None:
    cleaned = token.strip().strip("'").strip('"')
    if not cleaned:
        return None
    if _is_ip_network(cleaned):
        return "ip_cidr", cleaned

    if cleaned.startswith(("+", ".")):
        normalized = cleaned.lstrip("+").lstrip(".")
        if not normalized:
            return None
        return "domain_suffix", normalized

    return "domain", cleaned


def _parse_logical_and_rule(line: str) -> dict[str, object] | None:
    components = re.findall(r"([A-Za-z0-9-]+,[^()]+)", line)
    parsed_rules: list[dict[str, str]] = []
    for component in components:
        matched = False
        for keyword, mapped in MAP_DICT.items():
            if component.startswith(f"{keyword},"):
                value = component.split(",", 1)[1].strip()
                if value:
                    parsed_rules.append({mapped: value})
                    matched = True
                break
        if not matched:
            return None

    if not parsed_rules:
        return None

    sorted_rules = _sort_list_of_dicts(cast(list[dict[str, object]], parsed_rules))
    return {"mode": "and", "rules": sorted_rules, "type": "logical"}


def _looks_like_android_package_name(value: str) -> bool:
    if "/" in value or "\\" in value or value.endswith((".exe", ".app", ".dll")):
        return False
    if "." not in value:
        return False

    parts = value.split(".")
    for index, part in enumerate(parts):
        if not part:
            return False
        if index == 0:
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", part) is None:
                return False
            continue
        if re.fullmatch(r"[A-Za-z0-9_]+", part) is None:
            return False
    return True


def _looks_like_process_name(value: str) -> bool:
    if "/" in value or "\\" in value:
        return False
    if value.endswith((".exe", ".app")):
        return True
    if re.fullmatch(r"[A-Za-z0-9_.-]+", value) is None:
        return False
    return "." not in value


def _strip_inline_comment(line: str) -> str:
    if "#" not in line:
        return line.strip()
    head, _, _tail = line.partition("#")
    return head.strip()


def _is_ip_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


def _sort_nested_dict(obj: object) -> object:
    if isinstance(obj, dict):
        return {key: _sort_nested_dict(obj[key]) for key in sorted(obj)}
    if isinstance(obj, list):
        if all(isinstance(item, dict) for item in obj):
            sorted_items = [
                _sort_nested_dict(item) for item in obj if isinstance(item, dict)
            ]
            typed_items = cast(list[dict[str, object]], sorted_items)
            return _sort_list_of_dicts(typed_items)
        return [_sort_nested_dict(item) for item in obj]
    return obj


def _sort_list_of_dicts(items: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(items, key=lambda item: tuple(item.keys()))


def _sort_logical_rules(items: list[dict[str, object]]) -> list[dict[str, object]]:
    return sorted(
        items,
        key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True),
    )
