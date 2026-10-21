"""Command line entry point for map, scan, audit, report, and serve."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from auditsift import __version__
from auditsift.config import load_settings
from auditsift.errors import AuditError
from auditsift.mcp_server import serve
from auditsift.models import SEVERITY_ORDER, AuditReport
from auditsift.pipeline import audit, exit_code_for
from auditsift.render import format_cost, render, write_bundle


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except AuditError as exc:
        print(f"auditsift: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditsift",
        description="Local-first multi-phase security audits with verified findings.",
    )
    parser.add_argument("--version", action="version", version=f"auditsift {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    map_cmd = sub.add_parser("map", help="inventory the attack surface offline")
    _add_target(map_cmd)
    map_cmd.add_argument("--format", choices=("text", "json"), default="text")
    map_cmd.set_defaults(func=cmd_map)

    scan = sub.add_parser("scan", help="run offline rule checks")
    _add_audit_flags(scan)
    scan.set_defaults(func=cmd_scan, use_llm=False, offline=False)

    full = sub.add_parser("audit", help="map, scan, optional triage and verify, then report")
    _add_audit_flags(full)
    full.add_argument(
        "--offline",
        action="store_true",
        help="do not call a model even if an API key is set",
    )
    full.add_argument(
        "--max-llm",
        type=int,
        default=40,
        help="maximum model calls for triage and, separately, for verify (default 40)",
    )
    full.set_defaults(func=cmd_audit, use_llm=True)

    report = sub.add_parser("report", help="render a saved auditsift JSON report")
    report.add_argument("json_path")
    report.add_argument("--format", choices=("text", "json", "sarif", "md"), default="md")
    report.add_argument("--out", help="write the rendered report to this file")
    report.set_defaults(func=cmd_report)

    serve_cmd = sub.add_parser("serve", help="MCP stdio server")
    serve_cmd.set_defaults(func=cmd_serve)
    return parser


def cmd_map(args: argparse.Namespace) -> int:
    report = audit(args.path, use_llm=False)
    if args.format == "json":
        sys.stdout.write(json.dumps(report.inventory, indent=2) + "\n")
        return 0
    inventory = report.inventory
    languages = ", ".join(f"{name} {count}" for name, count in inventory["languages"].items())
    print(f"auditsift map  {report.target}")
    print(f"  files        {inventory['files']}")
    print(f"  languages    {languages or 'none'}")
    print(f"  entrypoints  {len(inventory['entry_points'])}")
    print(f"  routes       {len(inventory['routes'])}")
    print(f"  manifests    {len(inventory['manifests'])}")
    print(f"  secrets      {len(inventory['secrets'])}")
    for route in inventory["routes"]:
        where = f"{route['path']}:{route['line']}"
        print(f"  route        {route['method']:<12} {route['pattern']}  {where}")
    for secret in inventory["secrets"]:
        print(f"  secret       {secret['kind']:<22} {secret['path']}:{secret['line']}  {secret['redacted']}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    report = audit(args.path, diff=args.diff, use_llm=False)
    return _emit(report, args)


def cmd_audit(args: argparse.Namespace) -> int:
    settings = load_settings()
    report = audit(
        args.path,
        diff=args.diff,
        settings=settings,
        use_llm=True,
        offline=args.offline,
        max_llm=args.max_llm,
    )
    return _emit(report, args)


def cmd_report(args: argparse.Namespace) -> int:
    path = Path(args.json_path)
    if not path.is_file():
        raise AuditError(f"report not found: {args.json_path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AuditError(f"report is not JSON: {exc}") from exc
    report = AuditReport.from_dict(data)
    text = render(report, args.format)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    if args.format != "text":
        print(format_cost(report.usage), file=sys.stderr)
    return 0


def cmd_serve(_args: argparse.Namespace) -> int:
    serve()
    return 0


def _emit(report: AuditReport, args: argparse.Namespace) -> int:
    if getattr(args, "out", None):
        write_bundle(report, args.out)
    sys.stdout.write(render(report, args.format))
    # Text reports already include the ledger. JSON and SARIF stay machine-readable,
    # so the same ledger is printed on stderr.
    if args.format != "text":
        print(format_cost(report.usage), file=sys.stderr)
    return exit_code_for(report.findings, args.fail_on)


def _add_target(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", default=".", help="file or directory (default: .)")


def _add_audit_flags(parser: argparse.ArgumentParser) -> None:
    _add_target(parser)
    parser.add_argument("--diff", help="git ref; only changed lines are reported")
    parser.add_argument("--format", choices=("text", "json", "sarif", "md"), default="text")
    parser.add_argument(
        "--fail-on",
        choices=SEVERITY_ORDER,
        help="exit 1 when a kept finding is at or above this severity",
    )
    parser.add_argument("--out", help="directory for auditsift.json, auditsift.sarif, and auditsift.md")
