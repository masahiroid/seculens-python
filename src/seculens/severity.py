"""Traceable advisory severity; CVSS 3.0/3.1 base scores and CVSS 4.0 scores."""

from __future__ import annotations

import json
import math
from typing import Any

from .cvss4 import cvss4_score
from .matcher import match_record, same_package

LEVELS = ("critical", "high", "medium", "low", "none", "unknown")
_RANK = {level: len(LEVELS) - index for index, level in enumerate(LEVELS)}


def cvss3_base(vector: Any) -> float | None:
    if not isinstance(vector, str) or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metrics: dict[str, str] = {}
    allowed = {
        "AV": "NALP",
        "AC": "LH",
        "PR": "NLH",
        "UI": "NR",
        "S": "UC",
        "C": "NLH",
        "I": "NLH",
        "A": "NLH",
        "E": "XUPFH",
        "RL": "XOTWU",
        "RC": "XURC",
        "CR": "XLMH",
        "IR": "XLMH",
        "AR": "XLMH",
        "MAV": "XNALP",
        "MAC": "XLH",
        "MPR": "XNLH",
        "MUI": "XNR",
        "MS": "XUC",
        "MC": "XNLH",
        "MI": "XNLH",
        "MA": "XNLH",
    }
    for token in vector.split("/")[1:]:
        pair = token.split(":")
        if len(pair) != 2:
            return None
        key, value = pair
        if key in metrics or key not in allowed or len(value) != 1 or value not in allowed[key]:
            return None
        metrics[key] = value
    if not all(key in metrics for key in ("AV", "AC", "PR", "UI", "S", "C", "I", "A")):
        return None
    impact_weight = {"N": 0, "L": 0.22, "H": 0.56}
    iss = 1 - math.prod(1 - impact_weight[metrics[key]] for key in ("C", "I", "A"))
    changed = metrics["S"] == "C"
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
    ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
    pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[metrics["PR"]]
    ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
    value = min((impact + 8.22 * av * ac * pr * ui) * (1.08 if changed else 1), 10)
    # FIRST Appendix A Roundup avoids binary floating-point over-rounding.
    integer = math.floor(value * 100000 + 0.5)
    return integer / 100000 if integer % 10000 == 0 else (math.floor(integer / 10000) + 1) / 10


def score_level(score: float) -> str:
    return (
        "critical"
        if score >= 9
        else "high"
        if score >= 7
        else "medium"
        if score >= 4
        else "low"
        if score > 0
        else "none"
    )


def merge_severity(*values: dict[str, Any]) -> dict[str, Any]:
    sources = {
        json.dumps(source, sort_keys=True): source
        for value in values
        for source in value.get("sources", [])
    }
    ordered = sorted(sources.values(), key=lambda s: (s["recordId"], s["field"], s["value"]))
    level = max((s["level"] for s in ordered), key=lambda x: _RANK[x], default="unknown")
    result: dict[str, Any] = {"level": level, "sources": ordered}
    scores = [s["score"] for s in ordered if s["level"] == level and "score" in s]
    if scores:
        result["score"] = max(scores)
    return result


def record_severity(record: dict[str, Any], component: dict[str, Any]) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    applicable = [
        (i, a)
        for i, a in enumerate(record["affected"])
        if same_package(component, a["package"])
        and match_record(component, dict(record, affected=[a])) == "affected"
    ]
    # OSV affected.severity overrides top-level severity for this affected entry.
    entries = [
        (f"affected[{i}].severity", a["severity"])
        if isinstance(a.get("severity"), list) and a["severity"]
        else ("severity", record.get("severity", []))
        for i, a in applicable
    ] or [("severity", record.get("severity", []))]
    for field, items in entries:
        if not isinstance(items, list):
            continue
        for index, entry in enumerate(items):
            if not isinstance(entry, dict) or not isinstance(entry.get("score"), str):
                continue
            kind = entry.get("type")
            score = (
                cvss3_base(entry["score"])
                if kind == "CVSS_V3"
                else cvss4_score(entry["score"])
                if kind == "CVSS_V4"
                else None
            )
            source: dict[str, Any] = {
                "recordId": record["id"],
                "field": f"{field}[{index}]",
                "type": str(entry.get("type", "unknown")),
                "value": entry["score"],
                "level": score_level(score) if score is not None else "unknown",
            }
            if score is not None:
                source["score"] = score
            sources.append(source)
    labels = [("database_specific.severity", record.get("database_specific", {}))]
    labels += [
        (f"affected[{i}].database_specific.severity", a.get("database_specific", {}))
        for i, a in applicable
    ]
    mapping = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MODERATE": "medium",
        "MEDIUM": "medium",
        "LOW": "low",
        "NONE": "none",
    }
    for field, data in labels:
        value = data.get("severity") if isinstance(data, dict) else None
        if isinstance(value, str):
            sources.append(
                {
                    "recordId": record["id"],
                    "field": field,
                    "type": "database_label",
                    "value": value,
                    "level": mapping.get(value.upper(), "unknown"),
                }
            )
    return merge_severity({"sources": sources})
