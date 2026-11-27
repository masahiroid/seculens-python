"""Waivers: recorded, expiring customer decisions. Waived findings stay in the report."""

from __future__ import annotations

import re
from datetime import date as _date
from typing import Any

KEYS = ("ruleId", "subject", "justification", "approvedBy", "expires")
WAIVER_LIMITATION = (
    "Waivers record customer-approved decisions that SecuLens does not verify; "
    "waived findings remain in the report and are excluded only from exit codes."
)


def _text(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def is_calendar_date(value: Any) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return False
    year, month, day = (int(part) for part in value.split("-"))
    try:
        _date(year, month, day)
    except ValueError:
        return False
    return True


def validate_waivers(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("Waiver file must be an object")
    for key in data:
        if key not in ("schemaVersion", "waivers"):
            raise ValueError(f"Waiver file has unknown key {key}")
    if data.get("schemaVersion") != "1.0":
        raise ValueError("Waiver file schemaVersion must be 1.0")
    if not isinstance(data.get("waivers"), list):
        raise ValueError("Waiver file waivers must be an array")
    for index, entry in enumerate(data["waivers"]):
        path = f"waivers[{index}]"
        if not isinstance(entry, dict):
            raise ValueError(f"Waiver {path} must be an object")
        for key in entry:
            if key not in KEYS:
                raise ValueError(f"Waiver {path} has unknown key {key}")
        for key in ("ruleId", "justification", "approvedBy"):
            if not _text(entry.get(key)):
                raise ValueError(f"Waiver {path}.{key} is required")
        if "subject" in entry and not _text(entry["subject"]):
            raise ValueError(f"Waiver {path}.subject must be a non-empty string")
        if not is_calendar_date(entry.get("expires")):
            raise ValueError(f"Waiver {path}.expires must be a YYYY-MM-DD date")
    return data


def _describe(waiver: dict[str, Any]) -> str:
    subject = f" on {waiver['subject']}" if "subject" in waiver else ""
    return f"{waiver['ruleId']}{subject}"


def _matches(waiver: dict[str, Any], finding: dict[str, Any]) -> bool:
    rule = waiver["ruleId"] == finding["ruleId"] or waiver["ruleId"] in finding.get("aliases", [])
    return rule and ("subject" not in waiver or waiver["subject"] == finding["subject"])


def apply_waivers(
    findings: list[dict[str, Any]], waivers: list[dict[str, Any]], date: str
) -> list[dict[str, Any]]:
    """Annotate findings covered by an active waiver (expires on or after ``date``) and
    append a review finding for each waiver that expired or matched nothing."""
    if not is_calendar_date(date):
        raise ValueError("Waiver date must be YYYY-MM-DD")
    used: set[int] = set()
    expired: set[int] = set()
    result: list[dict[str, Any]] = []
    for finding in findings:
        indexes = [i for i, waiver in enumerate(waivers) if _matches(waiver, finding)]
        used.update(indexes)
        expired.update(i for i in indexes if waivers[i]["expires"] < date)
        active = next((i for i in indexes if waivers[i]["expires"] >= date), None)
        if active is None:
            result.append(finding)
            continue
        waiver = waivers[active]
        result.append(
            {
                **finding,
                "waiver": {
                    "source": f"waivers[{active}]",
                    "justification": waiver["justification"],
                    "approvedBy": waiver["approvedBy"],
                    "expires": waiver["expires"],
                },
            }
        )
    for i, waiver in enumerate(waivers):
        if i in expired:
            result.append(
                {
                    "category": "quality",
                    "ruleId": "WAIVER-EXPIRED",
                    "subject": f"waivers[{i}]",
                    "status": "review",
                    "summary": "Waiver expired",
                    "evidence": (
                        f"{_describe(waiver)} expired {waiver['expires']}; "
                        f"approved by {waiver['approvedBy']}"
                    ),
                    "recommendation": (
                        "Remediate the finding or renew the waiver after a new review."
                    ),
                }
            )
        elif i not in used:
            result.append(
                {
                    "category": "quality",
                    "ruleId": "WAIVER-UNMATCHED",
                    "subject": f"waivers[{i}]",
                    "status": "review",
                    "summary": "Waiver matched no finding",
                    "evidence": f"{_describe(waiver)}; expires {waiver['expires']}",
                    "recommendation": "Remove the waiver, or correct its ruleId or subject.",
                }
            )
    return result


def unwaived(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Findings that count toward exit codes: everything without an active waiver."""
    return [finding for finding in findings if "waiver" not in finding]
