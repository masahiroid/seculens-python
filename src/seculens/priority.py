"""Customer-context prioritization. Severity is never changed; adjustments record their assertion."""

from __future__ import annotations

from typing import Any

EFFECTS = {
    "exposure": {"internet": 1, "internal": 0, "isolated": -1},
    "reachability": {"reachable": 1, "unknown": 0, "not-reachable": -1},
    "criticality": {"high": 1, "medium": 0, "low": -1},
}
# Unrated advisories rank with High until reviewed, so missing metadata never lowers urgency.
BASELINE = {"critical": 1, "high": 2, "medium": 3, "low": 4, "none": 4, "unknown": 2}


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _validate_entry(entry: Any, path: str, identity: tuple[str, ...]) -> None:
    if not isinstance(entry, dict):
        raise ValueError(f"Policy {path} must be an object")
    for key in entry:
        if key not in EFFECTS and key != "justification" and key not in identity:
            raise ValueError(f"Policy {path} has unknown key {key}")
    stated = [factor for factor in EFFECTS if factor in entry]
    if not stated:
        raise ValueError(f"Policy {path} must state at least one factor")
    for factor in stated:
        if not isinstance(entry[factor], str) or entry[factor] not in EFFECTS[factor]:
            raise ValueError(f"Policy {path}.{factor} has an unsupported value")
    if not _is_text(entry.get("justification")):
        raise ValueError(f"Policy {path}.justification is required")


def validate_context(context: Any) -> dict[str, Any]:
    if not isinstance(context, dict):
        raise ValueError("Policy context must be an object")
    for key in context:
        if key not in ("defaults", "components"):
            raise ValueError(f"Policy context has unknown key {key}")
    if "defaults" in context:
        _validate_entry(context["defaults"], "context.defaults", ())
    if "components" in context:
        if not isinstance(context["components"], list):
            raise ValueError("Policy context.components must be an array")
        for index, entry in enumerate(context["components"]):
            path = f"context.components[{index}]"
            _validate_entry(entry, path, ("name", "ecosystem"))
            if not _is_text(entry.get("name")):
                raise ValueError(f"Policy {path}.name is required")
            if "ecosystem" in entry and entry["ecosystem"] not in ("npm", "PyPI", "Packagist"):
                raise ValueError(f"Policy {path}.ecosystem is not supported")
    return context


def component_priority(
    level: str, component: dict[str, Any] | None, context: dict[str, Any]
) -> dict[str, Any]:
    component = component or {}
    factors: list[dict[str, Any]] = []
    for factor, effects in EFFECTS.items():
        source, entry = "context.defaults", context.get("defaults")
        for index, candidate in enumerate(context.get("components", [])):
            if (
                factor in candidate
                and candidate["name"] == component.get("name")
                and (
                    "ecosystem" not in candidate
                    or candidate["ecosystem"] == component.get("ecosystem")
                )
            ):
                source, entry = f"context.components[{index}]", candidate
                break
        if entry is not None and factor in entry:
            factors.append(
                {
                    "factor": factor,
                    "value": entry[factor],
                    "effect": effects[entry[factor]],
                    "source": source,
                    "justification": entry["justification"],
                }
            )
    baseline = BASELINE[level]
    raised = sum(factor["effect"] for factor in factors)
    # A score of None has no impact to weigh, so context cannot raise it.
    rank = baseline if level == "none" else min(max(baseline - raised, 1), 4)
    return {"level": f"P{rank}", "baseline": f"P{baseline}", "factors": factors}


def apply_priorities(
    findings: list[dict[str, Any]], components: list[dict[str, Any]], context: dict[str, Any]
) -> None:
    by_id = {component["id"]: component for component in components}
    for finding in findings:
        if finding["category"] == "vulnerability":
            finding["priority"] = component_priority(
                finding.get("severity", {}).get("level", "unknown"),
                by_id.get(finding["subject"]),
                context,
            )
