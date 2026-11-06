"""Policy decisions over a parsed SPDX license expression."""

from __future__ import annotations

from typing import Any

from license_expression import AND, OR, ExpressionError, get_spdx_licensing

from .priority import validate_context

_LICENSING = get_spdx_licensing()


def validate_policy(policy: Any) -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise ValueError("Policy must be a JSON object")
    for key in ("allow", "deny"):
        if key in policy and (
            not isinstance(policy[key], list) or any(not isinstance(x, str) for x in policy[key])
        ):
            raise ValueError("Policy allow/deny must be string arrays")
    if "context" in policy:
        validate_context(policy["context"])
    return policy


def evaluate_license(expression: str, policy: dict[str, Any]) -> str:
    if expression in ("NOASSERTION", "NONE", ""):
        return "review"
    try:
        parsed = _LICENSING.parse(expression, validate=True, strict=True)

        def walk(node: Any) -> str:
            if isinstance(node, (AND, OR)):
                decisions = [walk(arg) for arg in node.args]
                if isinstance(node, OR):
                    if "allowed" in decisions:
                        return "allowed"
                    return "denied" if all(x == "denied" for x in decisions) else "review"
                if "denied" in decisions:
                    return "denied"
                return "allowed" if all(x == "allowed" for x in decisions) else "review"
            identity = str(node)
            if identity in policy.get("deny", []):
                return "denied"
            return "allowed" if identity in policy.get("allow", []) else "review"

        return walk(parsed)
    except (ExpressionError, ValueError, TypeError):
        return "review"


def license_findings(component: dict[str, Any], policy: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    for expression in component["licenses"] or ["NOASSERTION"]:
        result = evaluate_license(expression, policy)
        if result == "allowed":
            continue
        denied = result == "denied"
        findings.append(
            {
                "category": "license",
                "ruleId": "LICENSE-DENIED" if denied else "LICENSE-REVIEW",
                "subject": component["id"],
                "status": "denied" if denied else "review",
                "summary": "License denied by policy" if denied else "License requires review",
                "evidence": expression,
                "recommendation": "Confirm the license, usage and distribution conditions against the customer policy.",
            }
        )
    return findings
