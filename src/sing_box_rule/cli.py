from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .build import build_from_config


def main() -> int:
    parser = argparse.ArgumentParser(prog="sing-box-rule")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build_parser = subparsers.add_parser(
        "build",
        help="clone source repo and build rule-set artifacts",
    )
    build_parser.add_argument(
        "--config",
        default="config.toml",
        help="path to the build configuration file",
    )

    args = parser.parse_args()
    if args.command != "build":
        parser.error(f"unsupported command: {args.command}")

    report = build_from_config(Path(args.config))
    if report.has_errors:
        for diagnostic in report.diagnostics:
            message = f"{diagnostic.severity}: {diagnostic.source}: {diagnostic.message}"
            print(message, file=sys.stderr)
        return 1

    for diagnostic in report.diagnostics:
        print(f"{diagnostic.severity}: {diagnostic.source}: {diagnostic.message}")
    print(f"converted {len(report.converted)} list files")
    print(f"copied {len(report.copied_markdown)} markdown files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
