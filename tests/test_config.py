from __future__ import annotations

from pathlib import Path

from sing_box_rule.config import load_config


def test_load_config(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "\n".join(
            [
                "[source]",
                'repo_url = "https://github.com/example/project"',
                'branch = "main"',
                'path = "rule/Clash"',
                "",
                "[output]",
                'directory = "ruleset"',
                "keep_json = true",
                "compile_srs = true",
                'manifest = "build-manifest.json"',
                "",
                "[conversion]",
                "keep_ambiguous_process_name = true",
                "expand_ip_asn = true",
                'asn_source = "ripe"',
                "asn_request_timeout_seconds = 10",
                "fail_on_asn_lookup_error = false",
            ]
        ),
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.source.repo_url == "https://github.com/example/project"
    assert config.source.branch == "main"
    assert config.source.path == "rule/Clash"
    assert config.output.directory == Path("ruleset")
    assert config.conversion.keep_ambiguous_process_name is True
    assert config.conversion.expand_ip_asn is True
    assert config.conversion.asn_source == "ripe"
    assert config.conversion.asn_request_timeout_seconds == 10
    assert config.conversion.fail_on_asn_lookup_error is False
