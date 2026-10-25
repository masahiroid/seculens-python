"""Model Context Protocol (MCP) stdio server implementation for SecuLens Python."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .analysis import analyze
from .core import scan_sbom, sha256
from .database import fetch_database, validate_database
from .licenses import evaluate_license
from .sbom import parse_sbom
from .word import write_word_report

MCP_TOOLS = [
    {
        "name": "seculens_scan",
        "description": "Scan SPDX or CycloneDX SBOM for known vulnerabilities (OSV) and license policy violations",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sbomPath": {
                    "type": "string",
                    "description": "Path to SPDX or CycloneDX JSON file",
                },
                "dbPath": {
                    "type": "string",
                    "description": "Path to local OSV JSON snapshot (optional, offline)",
                },
                "fetchOsv": {
                    "type": "boolean",
                    "description": "Fetch candidate advisories from api.osv.dev if dbPath not provided (default: true)",
                },
                "policy": {
                    "type": "object",
                    "description": "License policy with allow and/or deny lists",
                    "properties": {
                        "allow": {"type": "array", "items": {"type": "string"}},
                        "deny": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
            "required": ["sbomPath"],
        },
    },
    {
        "name": "seculens_analyze",
        "description": "Perform static AST analysis and supply chain inspection on source directory and lifecycle scripts",
        "inputSchema": {
            "type": "object",
            "properties": {
                "directory": {
                    "type": "string",
                    "description": "Directory containing source code and package files",
                },
            },
            "required": ["directory"],
        },
    },
    {
        "name": "seculens_check_license",
        "description": "Evaluate an SPDX license expression against allow/deny lists",
        "inputSchema": {
            "type": "object",
            "properties": {
                "expression": {
                    "type": "string",
                    "description": "SPDX license expression (e.g. 'MIT OR Apache-2.0')",
                },
                "allow": {"type": "array", "items": {"type": "string"}},
                "deny": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["expression"],
        },
    },
    {
        "name": "seculens_generate_report",
        "description": "Generate customer Word (.docx) and JSON reports from SBOM and analysis results",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sbomPath": {"type": "string", "description": "Path to SBOM JSON"},
                "outputDir": {
                    "type": "string",
                    "description": "Directory where report.docx and report.json will be saved",
                },
                "customer": {"type": "string", "description": "Customer name"},
                "target": {"type": "string", "description": "Target system name"},
                "dbPath": {
                    "type": "string",
                    "description": "Path to local OSV JSON snapshot (optional)",
                },
                "sourceDir": {
                    "type": "string",
                    "description": "Optional source directory for AST analysis",
                },
                "lang": {
                    "type": "string",
                    "enum": ["en", "ja"],
                    "description": "Report language: en or ja",
                },
            },
            "required": ["sbomPath", "outputDir"],
        },
    },
]


def handle_mcp_request(request: dict[str, Any]) -> dict[str, Any] | None:
    req_id = request.get("id")
    method = request.get("method")
    params = request.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "seculens-python", "version": "1.1.0"},
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOLS}}

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        try:
            content_text = ""
            if name == "seculens_scan":
                sbom_path = Path(args["sbomPath"]).resolve()
                raw = sbom_path.read_text(encoding="utf-8")
                sbom = parse_sbom(json.loads(raw))
                records: list[dict[str, Any]] = []
                db_source = "None"
                db_hash = ""
                if "dbPath" in args and args["dbPath"]:
                    db_file = Path(args["dbPath"]).resolve()
                    db_text = db_file.read_text(encoding="utf-8")
                    records = validate_database(json.loads(db_text))
                    db_source = db_file.name
                    db_hash = sha256(db_text)
                elif args.get("fetchOsv", True):
                    records = fetch_database(sbom["components"])
                    db_source = "OSV API snapshot"
                    db_hash = sha256(json.dumps(records))
                policy = args.get("policy", {})
                report = scan_sbom(
                    raw,
                    records,
                    database_source=db_source,
                    database_hash=db_hash,
                    policy=policy,
                )
                affected_vulns = sum(
                    1
                    for f in report["findings"]
                    if f.get("category") == "vulnerability" and f.get("status") == "affected"
                )
                denied_licenses = sum(
                    1
                    for f in report["findings"]
                    if f.get("category") == "license" and f.get("status") == "denied"
                )
                content_text = json.dumps(
                    {
                        "summary": {
                            "components": len(report["sbom"]["components"]),
                            "findings": len(report["findings"]),
                            "affectedVulnerabilities": affected_vulns,
                            "deniedLicenses": denied_licenses,
                        },
                        "findings": report["findings"],
                    },
                    indent=2,
                )
            elif name == "seculens_analyze":
                findings = analyze(Path(args["directory"]).resolve())
                content_text = json.dumps(
                    {
                        "totalFindings": len(findings),
                        "securityReviewCandidates": sum(
                            1 for f in findings if f.get("category") == "security"
                        ),
                        "qualityFindings": sum(
                            1 for f in findings if f.get("category") == "quality"
                        ),
                        "findings": findings,
                    },
                    indent=2,
                )
            elif name == "seculens_check_license":
                expr = args["expression"]
                policy = {"allow": args.get("allow", []), "deny": args.get("deny", [])}
                status = evaluate_license(expr, policy)
                content_text = json.dumps({"expression": expr, "status": status})
            elif name == "seculens_generate_report":
                sbom_path = Path(args["sbomPath"]).resolve()
                raw = sbom_path.read_text(encoding="utf-8")
                sbom = parse_sbom(json.loads(raw))
                records = []
                db_text = "{}"
                if "dbPath" in args and args["dbPath"]:
                    db_file = Path(args["dbPath"]).resolve()
                    db_text = db_file.read_text(encoding="utf-8")
                    records = validate_database(json.loads(db_text))
                    db_source = db_file.name
                else:
                    records = fetch_database(sbom["components"])
                    db_text = json.dumps(records)
                    db_source = "OSV API snapshot"
                report = scan_sbom(
                    raw,
                    records,
                    customer=args.get("customer", "Customer"),
                    target=args.get("target", sbom_path.name),
                    database_source=db_source,
                    database_hash=sha256(db_text),
                )
                if "sourceDir" in args and args["sourceDir"]:
                    report["findings"].extend(analyze(Path(args["sourceDir"]).resolve()))
                out_dir = Path(args["outputDir"]).resolve()
                out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                json_path = out_dir / "report.json"
                docx_path = out_dir / "report.docx"
                json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
                write_word_report(
                    report,
                    docx_path,
                    language=args.get("lang", "en"),
                    style="customer",
                )
                content_text = json.dumps(
                    {
                        "status": "success",
                        "reportJson": str(json_path),
                        "reportDocx": str(docx_path),
                        "findingsCount": len(report["findings"]),
                    },
                    indent=2,
                )
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {name}"},
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": content_text}], "isError": False},
            }
        except Exception as err:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": f"Error: {err}"}], "isError": True},
            }

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def run_mcp_server() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            res = handle_mcp_request(req)
            if res is not None:
                sys.stdout.write(json.dumps(res) + "\n")
                sys.stdout.flush()
        except Exception:
            sys.stdout.write(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "Parse error"},
                    }
                )
                + "\n"
            )
            sys.stdout.flush()

