# sing-box-rule

Sync a configured Clash rules directory from an upstream Git repository, convert every `*.list`
file into a sing-box rule-set JSON file, compile it into `.srs`, and copy Markdown files with
the same relative layout.

## Configuration

Edit [config.toml](/Users/nextpage/Documents/python/sing-box-rule/config.toml):

- `[source]` defines `repo_url`, `branch`, and the exact `path` to scan in the upstream repo.
- `[output]` defines the managed output directory plus artifact options.
- `[conversion]` controls Clash-specific compatibility behavior:
  - `keep_ambiguous_process_name` preserves unclear `PROCESS-NAME` values as logical `or`
    between `process_name` and `package_name`
  - `expand_ip_asn` expands `IP-ASN` rules into `ip_cidr` prefixes through RIPEstat
  - `fail_on_asn_lookup_error` decides whether ASN lookup failures fail the build or only warn

The build is intentionally stateless: every run clones the upstream repository with `--depth 1`
into a temporary directory, reads only the configured path, writes generated files into the output
directory, then removes the temporary clone.

The GitHub Actions workflow only runs the upstream sync and commits regenerated artifacts.
Development checks stay local.

For automatic commits to work, the target branch must allow pushes from `GITHUB_TOKEN` /
`github-actions[bot]`. If branch protection blocks bot pushes, the workflow will build
successfully but fail at the final push step.

## Usage

```bash
uv run python src/main.py build --config config.toml
```

## Development

The project includes [uv.toml](/Users/nextpage/Documents/python/sing-box-rule/uv.toml) so `uv`
uses the USTC PyPI mirror by default in mainland China.

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run python src/main.py build --config config.toml
```

## Generated Output

Everything under the configured output directory is managed output. The builder clears that
directory before each run, then regenerates:

- `*.json` intermediate sing-box rule-set files
- `*.srs` compiled rule-set files
- copied Markdown files
- `build-manifest.json`
