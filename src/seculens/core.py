"""Shared report contract, assessment checks and advisory alias consolidation."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .database import validate_database
from .licenses import license_findings, validate_policy
from .matcher import match_record, same_package, supported_version
from .sbom import parse_sbom
from .severity import merge_severity, record_severity

LIMITATIONS = [
    "No match means no matching record in the supplied database snapshot, not absence of vulnerabilities.",
    "License policy checks are not a legal compliance determination.",
    "AST rules identify review candidates and complexity, not proven exploitability.",
    "SBOM content and package identifiers are supplied by the generating tool.",
    "Packagist matching supports stable numeric versions and SemVer prereleases only; Composer branches and other version forms may be unassessed.",
]


def sha256(value: str | bytes) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def scan_sbom(
    sbom_text: str,
    records: list[dict[str, Any]],
    *,
    customer: str = "Customer",
    target: str = "SBOM",
    policy: dict[str, Any] | None = None,
    database_source: str = "OSV snapshot",
    database_hash: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    sbom = parse_sbom(json.loads(sbom_text))
    validate_database(records)
    policy = validate_policy({} if policy is None else policy)
    report: dict[str, Any] = {
        "schemaVersion": "1.1",
        "tool": {"name": "SecuLens", "version": "1.1.0"},
        "createdAt": created_at
        or datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "customer": customer,
        "target": target,
        "sbomSha256": sha256(sbom_text),
        "database": {
            "source": database_source,
            "sha256": database_hash
            or sha256(json.dumps(records, ensure_ascii=False, separators=(",", ":"))),
        },
        "sbom": sbom,
        "checks": [],
        "findings": [],
        "limitations": list(LIMITATIONS),
    }
    for component in sbom["components"]:
        report["findings"].extend(license_findings(component, policy))
        if not supported_version(component):
            reason = (
                "Supported package URL required (npm, pypi or composer)"
                if not component.get("ecosystem")
                else "Package version is missing"
                if not component.get("version")
                else "Unsupported package version syntax"
            )
            report["checks"].append(
                {
                    "componentId": component["id"],
                    "status": "unassessed",
                    "recordsChecked": 0,
                    "reason": reason,
                }
            )
            report["findings"].append(
                {
                    "category": "coverage",
                    "ruleId": "PACKAGE-IDENTITY",
                    "subject": component["id"],
                    "status": "unassessed",
                    "summary": "Component could not be assessed",
                    "evidence": reason,
                    "recommendation": "Regenerate the SBOM with complete package URLs and versions.",
                }
            )
            continue
        candidates = [
            r for r in records if any(same_package(component, a["package"]) for a in r["affected"])
        ]
        matched, uncertain = False, False
        for record in candidates:
            result = match_record(component, record)
            if result == "not-affected":
                continue
            if result == "unknown":
                uncertain = True
                report["findings"].append(
                    {
                        "category": "coverage",
                        "ruleId": record["id"],
                        "subject": component["id"],
                        "status": "unassessed",
                        "summary": "Advisory could not be fully evaluated",
                        "evidence": f"{component['name']}@{component['version']}; unsupported or incomplete version range",
                        "recommendation": "Review the advisory and package version manually.",
                    }
                )
                continue
            matched = True
            report["findings"].append(
                {
                    "category": "vulnerability",
                    "ruleId": record["id"],
                    "subject": component["id"],
                    "status": "affected",
                    "summary": record.get("summary") or record["id"],
                    "evidence": f"{component['ecosystem']}:{component['name']}@{component['version']}; matched against affected versions/ranges in {record['id']}",
                    "recommendation": "Review the advisory references for a fixed version and validate the upgrade.",
                    "severity": record_severity(record, component),
                    "aliases": record.get("aliases", []),
                    "references": [ref["url"] for ref in record.get("references", [])],
                }
            )
        check = {
            "componentId": component["id"],
            "status": "unassessed" if uncertain else "matched" if matched else "no-match",
            "recordsChecked": len(candidates),
        }
        if uncertain:
            check["reason"] = "One or more candidate records require manual review"
        report["checks"].append(check)
    groups: list[dict[str, Any]] = []
    for finding in report["findings"]:
        if finding["category"] != "vulnerability":
            groups.append(finding)
            continue
        merged = dict(finding)
        changed = True
        while changed:
            changed = False
            for index in range(len(groups) - 1, -1, -1):
                other = groups[index]
                if other["category"] != "vulnerability" or other["subject"] != merged["subject"]:
                    continue
                identities = {merged["ruleId"], *merged["aliases"]}
                if not identities.intersection({other["ruleId"], *other["aliases"]}):
                    continue
                all_ids = sorted(identities | {other["ruleId"], *other["aliases"]})
                merged.update(
                    severity=merge_severity(merged["severity"], other["severity"]),
                    ruleId=all_ids[0],
                    aliases=all_ids[1:],
                    references=sorted(set(merged["references"] + other["references"])),
                    evidence=" | ".join(sorted([merged["evidence"], other["evidence"]])),
                )
                groups.pop(index)
                changed = True
        groups.append(merged)
    report["findings"] = sorted(groups, key=lambda f: (f["category"], f["subject"], f["ruleId"]))
    return report
