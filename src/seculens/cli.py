"""Native Python CLI. Syft is an optional external SBOM generator."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .analysis import analyze
from .core import scan_sbom, sha256
from .database import fetch_database, validate_database
from .integrity import check_lockfile_integrity, check_package_cool_off
from .mcp import run_mcp_server
from .sbom import parse_sbom
from .wizard import wizard
from .word import write_word_report


def _json(text: str):
    return json.loads(text)


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print("\nCancelled / 中止しました。", file=sys.stderr)
        return 130


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="seculens", description="SBOM assessment and evidence-based customer reports"
    )
    parser.add_argument("--version", action="version", version="1.0.0")
    commands = parser.add_subparsers(dest="command", required=True)
    interactive = commands.add_parser("wizard", help="Interactive setup in English or Japanese")
    interactive.add_argument("--lang", choices=("en", "ja"))
    commands.add_parser("mcp", help="Start the SecuLens Model Context Protocol (MCP) stdio server")
    sbom = commands.add_parser("sbom", help="Generate CycloneDX or SPDX JSON using Syft")
    sbom.add_argument("project", type=Path)
    sbom.add_argument("--format", choices=("cyclonedx", "spdx"), default="cyclonedx")
    sbom.add_argument("--syft", default="syft", help="Syft executable path")
    sbom.add_argument("-o", "--output", required=True, type=Path)
    scan = commands.add_parser("scan", help="Assess a JSON SBOM using OSV candidate records")
    scan.add_argument("sbom", type=Path)
    database = scan.add_mutually_exclusive_group(required=True)
    database.add_argument("--db", type=Path)
    database.add_argument(
        "--fetch-osv", action="store_true", help="Send package names/ecosystems to OSV"
    )
    scan.add_argument("--policy", type=Path)
    scan.add_argument("--source", type=Path, help="Run Python AST review rules")
    scan.add_argument(
        "--cool-off",
        type=int,
        metavar="DAYS",
        help="Flag packages released within the last N days (cool-off period)",
    )
    scan.add_argument("--customer", default="Customer")
    scan.add_argument("--target", help="Human-readable system or project name")
    scan.add_argument("--report-style", choices=("standard", "customer"), default="standard")
    scan.add_argument("--issuer", default="", help="Report preparer name for the customer cover")
    scan.add_argument("--lang", choices=("en", "ja"), default="en")
    scan.add_argument("-o", "--output", type=Path, default=Path("reports"))
    scan.add_argument("--fail-on-findings", action="store_true")
    args = list(sys.argv[1:] if argv is None else argv)
    ui_language = "en"
    if not args:
        args, ui_language = wizard()
        if args is None:
            return 0
    opts = parser.parse_args(args)
    if opts.command == "wizard":
        args, ui_language = wizard(opts.lang)
        if args is None:
            return 0
        opts = parser.parse_args(args)
    if opts.command == "mcp":
        run_mcp_server()
        return 0
    try:
        if opts.command == "sbom":
            if not opts.project.is_dir():
                raise ValueError("Project must be a directory")
            output_format = "cyclonedx-json" if opts.format == "cyclonedx" else "spdx-json"
            result = subprocess.run(
                [opts.syft, "scan", f"dir:{opts.project.resolve()}", "-o", output_format],
                capture_output=True,
                text=True,
                check=True,
                timeout=300,
                env={**os.environ, "SYFT_CHECK_FOR_APP_UPDATE": "false"},
            )
            parse_sbom(_json(result.stdout))
            opts.output.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix=".seculens-", dir=opts.output.parent) as folder:
                temporary = Path(folder) / "sbom.json"
                temporary.write_text(result.stdout, encoding="utf-8")
                temporary.chmod(0o600)
                temporary.replace(opts.output)
            print(
                f"SBOMを保存しました: {opts.output}"
                if ui_language == "ja"
                else f"SBOM written to {opts.output}"
            )
            return 0
        # Read every input before writing output evidence, even when paths overlap.
        input_text = opts.sbom.read_text(encoding="utf-8")
        parsed = parse_sbom(_json(input_text))
        if opts.db:
            database_text = opts.db.read_text(encoding="utf-8")
            records = validate_database(_json(database_text))
        else:
            print(
                "OSVから取得中: パッケージ名とエコシステムをapi.osv.devへ送信します。"
                if ui_language == "ja"
                else "Fetching OSV candidates: package names and ecosystems are sent to api.osv.dev.",
                file=sys.stderr,
            )
            records = fetch_database(parsed["components"])
            database_text = json.dumps({"records": records}, ensure_ascii=False, indent=2) + "\n"
        policy = _json(opts.policy.read_text(encoding="utf-8")) if opts.policy else {}
        report = scan_sbom(
            input_text,
            records,
            customer=opts.customer,
            target=opts.target or opts.sbom.name,
            policy=policy,
            database_source=opts.db.name if opts.db else "OSV API candidate snapshot",
            database_hash=sha256(database_text),
        )
        if opts.source:
            report["findings"].extend(analyze(opts.source))
            report["findings"].extend(check_lockfile_integrity(opts.source, parsed))
            report["sourceAnalysis"] = {"language": "Python", "target": opts.source.resolve().name}
        else:
            report["findings"].extend(check_lockfile_integrity(opts.sbom.parent, parsed))
        if opts.cool_off:
            report["findings"].extend(
                check_package_cool_off(parsed["components"], min_days=opts.cool_off)
            )
        opts.output.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(prefix=".seculens-", dir=opts.output) as folder:
            temporary = Path(folder)
            (temporary / "sbom.json").write_text(input_text, encoding="utf-8")
            (temporary / "database.json").write_text(database_text, encoding="utf-8")
            (temporary / "report.json").write_text(
                json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            write_word_report(
                report,
                temporary / "report.docx",
                opts.lang,
                style=opts.report_style,
                issuer=opts.issuer,
            )
            for name in ("sbom.json", "database.json", "report.json", "report.docx"):
                artifact = temporary / name
                artifact.chmod(0o600)
                artifact.replace(opts.output / name)
        print(
            f"構成部品 {len(parsed['components'])}件、指摘 {len(report['findings'])}件。レポート: {opts.output}"
            if ui_language == "ja"
            else f"{len(parsed['components'])} components; {len(report['findings'])} findings. Reports: {opts.output}"
        )
        if opts.fail_on_findings and any(
            f["status"] in ("affected", "denied") or f["category"] == "security"
            for f in report["findings"]
        ):
            return 1
        return 2 if any(f["status"] == "unassessed" for f in report["findings"]) else 0
    except Exception as error:
        print(f"SecuLens: {error}", file=sys.stderr)
        return 2
