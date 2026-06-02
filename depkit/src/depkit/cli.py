from __future__ import annotations

import argparse
from pathlib import Path

from depkit.planner import assess, build_plan
from depkit.render import render_plan, render_risks, render_scan
from depkit.scanner import scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="depkit", description="Plan dependency upgrades before they sprawl.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command in ("scan", "risk", "plan"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("path", nargs="?", default=".", help="Repository path")

    args = parser.parse_args(argv)
    root = Path(args.path)
    dependencies = scan(root)

    if args.command == "scan":
        print(render_scan(dependencies))
        return 0
    if args.command == "risk":
        print(render_risks(assess(dependencies)))
        return 0
    if args.command == "plan":
        print(render_plan(build_plan(dependencies)))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
