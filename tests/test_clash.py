from __future__ import annotations

import json
from pathlib import Path

from sing_box_rule.clash import build_ruleset, parse_clash_list_file, ruleset_to_json


def test_parse_clash_list_file_basic(tmp_path: Path) -> None:
    source = tmp_path / "sample.list"
    source.write_text(
        "\n".join(
            [
                "# comment",
                "DOMAIN,example.com",
                "DOMAIN-SUFFIX,example.org",
                "IP-CIDR,1.1.1.0/24",
                "DOMAIN,example.com",
                "AND,((DOMAIN,foo.com),(IP-CIDR,10.0.0.0/8))",
            ]
        ),
        encoding="utf-8",
    )

    result = parse_clash_list_file(source, keep_ambiguous_process_name=True)

    assert result.diagnostics == []
    assert build_ruleset(result) == {
        "rules": [
            {"domain": ["example.com"]},
            {"domain_suffix": ["example.org"]},
            {"ip_cidr": ["1.1.1.0/24"]},
            {
                "mode": "and",
                "rules": [{"domain": "foo.com"}, {"ip_cidr": "10.0.0.0/8"}],
                "type": "logical",
            },
        ],
        "version": 2,
    }


def test_ruleset_to_json_is_stable(tmp_path: Path) -> None:
    source = tmp_path / "ordered.list"
    source.write_text(
        "\n".join(
            [
                "DOMAIN-SUFFIX,b.example",
                "DOMAIN-SUFFIX,a.example",
                "DOMAIN,z.example",
                "DOMAIN,a.example",
            ]
        ),
        encoding="utf-8",
    )

    result = parse_clash_list_file(source, keep_ambiguous_process_name=True)
    payload = json.loads(ruleset_to_json(build_ruleset(result)))

    assert payload == {
        "rules": [
            {"domain": ["a.example", "z.example"]},
            {"domain_suffix": ["a.example", "b.example"]},
        ],
        "version": 2,
    }


def test_process_name_is_classified_into_package_or_process_or_ambiguous(tmp_path: Path) -> None:
    source = tmp_path / "process.list"
    source.write_text(
        "\n".join(
            [
                "PROCESS-NAME,Telegram.exe",
                "PROCESS-NAME,org.telegram.messenger",
                "PROCESS-NAME,maybe.mixed-name",
            ]
        ),
        encoding="utf-8",
    )

    result = parse_clash_list_file(source, keep_ambiguous_process_name=True)

    assert build_ruleset(result) == {
        "rules": [
            {
                "mode": "or",
                "rules": [
                    {"package_name": ["maybe.mixed-name"]},
                    {"process_name": ["maybe.mixed-name"]},
                ],
                "type": "logical",
            },
            {"package_name": ["org.telegram.messenger"]},
            {"process_name": ["Telegram.exe"]},
        ],
        "version": 2,
    }
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].severity == "warning"
    assert result.diagnostics[0].source == f"{source}:3"
    assert (
        result.diagnostics[0].message
        == "ambiguous PROCESS-NAME preserved as logical or(process_name, package_name)"
    )


def test_android_package_name_allows_numeric_later_segments(tmp_path: Path) -> None:
    source = tmp_path / "package.list"
    source.write_text("PROCESS-NAME,com.example.123app\n", encoding="utf-8")

    result = parse_clash_list_file(source, keep_ambiguous_process_name=True)

    assert build_ruleset(result) == {
        "rules": [{"package_name": ["com.example.123app"]}],
        "version": 2,
    }
    assert result.diagnostics == []


def test_ip_asn_expands_into_ip_cidr(tmp_path: Path) -> None:
    source = tmp_path / "asn.list"
    source.write_text(
        "\n".join(
            [
                "DOMAIN,example.com",
                "IP-ASN,20473,no-resolve",
                "IP-CIDR,1.1.1.0/24",
            ]
        ),
        encoding="utf-8",
    )

    parsed = parse_clash_list_file(source, keep_ambiguous_process_name=True)
    ruleset = build_ruleset(
        parsed,
        asn_prefixes={"20473": ["24.199.123.28/32", "64.23.132.171/32"]},
    )

    assert ruleset == {
        "rules": [
            {"domain": ["example.com"]},
            {"ip_cidr": ["1.1.1.0/24", "24.199.123.28/32", "64.23.132.171/32"]},
        ],
        "version": 2,
    }


def test_and_rule_with_unknown_component_is_skipped(tmp_path: Path) -> None:
    source = tmp_path / "logical.list"
    source.write_text(
        "AND,((DOMAIN,example.com),(PROCESS-NAME,test-app))\n",
        encoding="utf-8",
    )

    result = parse_clash_list_file(source, keep_ambiguous_process_name=True)

    assert build_ruleset(result) == {"rules": [], "version": 2}
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].severity == "warning"
    assert result.diagnostics[0].source == f"{source}:1"
    assert result.diagnostics[0].message == "unable to parse logical AND rule, skipped"


def test_and_rule_supports_lowercase_components(tmp_path: Path) -> None:
    source = tmp_path / "logical-lower.list"
    source.write_text(
        "AND,((ip-cidr,1.1.1.0/24),(DOMAIN,example.com))\n",
        encoding="utf-8",
    )

    result = parse_clash_list_file(source, keep_ambiguous_process_name=True)

    assert build_ruleset(result) == {
        "rules": [
            {
                "mode": "and",
                "rules": [{"domain": "example.com"}, {"ip_cidr": "1.1.1.0/24"}],
                "type": "logical",
            }
        ],
        "version": 2,
    }
    assert result.diagnostics == []
