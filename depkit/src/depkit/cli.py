from __future__ import annotations

import argparse
import sys
from pathlib import Path

from depkit.planner import assess, build_plan
from depkit.render import render_plan, render_risks, render_scan, render_warnings
from depkit.scanner import scan_with_warnings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="depkit", description="Plan dependency upgrades before they sprawl.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command in ("scan", "risk", "plan"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("path", nargs="?", default=".", help="Repository path")

    args = parser.parse_args(argv)
    root = Path(args.path)
    if not root.exists():
        print(f"depkit: path does not exist: {root}", file=sys.stderr)
        return 2
    if not root.is_dir():
        print(f"depkit: path is not a directory: {root}", file=sys.stderr)
        return 2
    result = scan_with_warnings(root)
    dependencies = list(result.dependencies)

    if args.command == "scan":
        _print_with_warnings(render_scan(dependencies), result.warnings)
        return 0
    if args.command == "risk":
        _print_with_warnings(render_risks(assess(dependencies)), result.warnings)
        return 0
    if args.command == "plan":
        _print_with_warnings(render_plan(build_plan(dependencies)), result.warnings)
        return 0
    return 2


def _print_with_warnings(body: str, warnings) -> None:
    warning_text = render_warnings(warnings)
    if warning_text:
        print(f"{body}\n\n{warning_text}")
    else:
        print(body)


if __name__ == "__main__":
    raise SystemExit(main())
