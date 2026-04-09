# sing-box-rule

`sing-box-rule` synchronizes a configured Clash rules directory from an upstream Git repository,
converts every `*.list` file into sing-box rule-set JSON, compiles `.srs` artifacts, and copies
Markdown files while preserving the original directory layout.

The project is designed around a stateless build flow:

- Each build performs a shallow clone of the upstream repository.
- Only the configured source path is scanned.
- Only `*.list` and Markdown files are processed.
- The temporary clone is removed after the build finishes.

## Configuration

Edit `config.toml` before running the builder.

### `[source]`

- `repo_url`: upstream Git repository URL
- `branch`: upstream branch to clone
- `path`: exact directory inside the upstream repository to scan

Example:

```toml
[source]
repo_url = "https://github.com/blackmatrix7/ios_rule_script"
branch = "master"
path = "rule/Clash"
```

### `[output]`

- `directory`: local output directory for generated artifacts
- `keep_json`: keep intermediate JSON rule-set files
- `compile_srs`: compile `.srs` files with `sing-box rule-set compile`
- `manifest`: manifest filename written into the output directory

### `[conversion]`

- `keep_ambiguous_process_name`: preserve ambiguous `PROCESS-NAME` values as logical `or`
  rules between `process_name` and `package_name`
- `expand_ip_asn`: expand `IP-ASN` rules into `ip_cidr` entries
- `asn_source`: ASN expansion backend
- `asn_request_timeout_seconds`: timeout for ASN lookups
- `fail_on_asn_lookup_error`: fail the build instead of emitting warnings when ASN expansion
  fails

## Usage

Run the build with the project CLI:

```bash
uv run --no-editable sing-box-rule build --config config.toml
```

The command prints warnings for skipped or ambiguous rules, then reports how many list files were
converted and how many Markdown files were copied.

## GitHub Actions

The repository is structured so that source code stays on `main`, while generated artifacts are
published to the `rule-set` branch.

- `main` keeps the source code, configuration, tests, and workflow definitions
- `rule-set` is intended to store generated `ruleset/` artifacts only
- The workflow builds from `main` and pushes fresh artifacts to `rule-set`

For automatic publishing to work, the target branch must allow pushes from `GITHUB_TOKEN` /
`github-actions[bot]`. If branch protection blocks bot pushes, the workflow can still build
successfully but will fail at the final publish step.

## Generated Output

Everything under the configured output directory is managed output. The builder clears that
directory before each run and regenerates:

- `*.json` intermediate sing-box rule-set files
- `*.srs` compiled rule-set files
- copied Markdown files
- `build-manifest.json`

## Development

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run --no-editable sing-box-rule build --config config.toml
```

## Acknowledgements

- Thanks to [SagerNet/sing-box](https://github.com/SagerNet/sing-box) for designing such amazing
  software.
- Thanks to [Toperlock/sing-box-geosite](https://github.com/Toperlock/sing-box-geosite) for the
  inspiration and conversion logic.
- Thanks to [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) for
  the carefully maintained data source.
- This project was completed with the help of Codex, and not a single line of code was written by
  a human.
