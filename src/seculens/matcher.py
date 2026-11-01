"""Independent ecosystem version comparisons against OSV affected ranges."""

from __future__ import annotations

import re
from typing import Any, Literal

from packaging.version import InvalidVersion
from packaging.version import Version as PepVersion
from semantic_version import Version as SemVersion

Match = Literal["affected", "not-affected", "unknown"]


def _canonical(name: str, ecosystem: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower()) if ecosystem == "PyPI" else name


def same_package(component: dict[str, Any], package: dict[str, Any]) -> bool:
    ecosystem = component.get("ecosystem")
    return ecosystem == package.get("ecosystem") and _canonical(
        component["name"], ecosystem
    ) == _canonical(package["name"], ecosystem)


# Composer stability order: dev < alpha < beta < RC < stable < patch.
_STABILITY = {
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "rc": 3,
    "stable": 4,
    "patch": 5,
    "pl": 5,
    "p": 5,
}
_COMPOSER = re.compile(
    r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:[._-]?(stable|beta|b|rc|alpha|a|patch|pl|p)(?:[.-]?(\d+))?)?([.-]?dev)?",
    re.IGNORECASE,
)


def _composer_key(text: str) -> tuple[int, ...] | None:
    """Composer VersionParser normalization; branch versions return None."""
    text = re.sub(r"^v", "", text.strip(), flags=re.IGNORECASE).split("+", 1)[0]
    m = _COMPOSER.fullmatch(text)
    if not m:
        return None
    rank = _STABILITY[m[5].lower()] if m[5] else (0 if m[7] else 4)
    dev = 0 if m[5] and m[7] else 1
    return (*(int(x or 0) for x in m.groups()[:4]), rank, int(m[6] or 0), dev)


def compare(left: str, right: str, ecosystem: str) -> int | None:
    if ecosystem == "Packagist":
        a, b = _composer_key(left), _composer_key(right)
        return None if a is None or b is None else (a > b) - (a < b)
    try:
        if ecosystem == "PyPI":
            a, b = PepVersion(left), PepVersion(right)
        else:

            def normalize(text: str) -> str:
                # npm's semver library accepts a leading v (and = prefix).
                if ecosystem == "npm":
                    text = text.strip().lstrip("v=")
                return text

            a, b = SemVersion(normalize(left)), SemVersion(normalize(right))
            # SemVer build metadata never affects precedence.
            a, b = a.truncate("prerelease"), b.truncate("prerelease")
        return (a > b) - (a < b)
    except (InvalidVersion, ValueError, TypeError):
        return None


def supported_version(component: dict[str, Any]) -> bool:
    version, ecosystem = component.get("version"), component.get("ecosystem")
    return bool(version and ecosystem and compare(version, version, ecosystem) is not None)


def match_record(component: dict[str, Any], record: dict[str, Any]) -> Match:
    if record.get("withdrawn"):
        return "not-affected"
    if not component.get("version") or not component.get("ecosystem"):
        return "unknown"
    version, ecosystem = component["version"], component["ecosystem"]
    unknown = False
    for affected in record["affected"]:
        if not same_package(component, affected["package"]):
            continue
        if any(
            v == version or compare(v, version, ecosystem) == 0
            for v in affected.get("versions", [])
        ):
            return "affected"
        ranges = affected.get("ranges", [])
        for version_range in ranges:
            if version_range["type"] not in ("SEMVER", "ECOSYSTEM"):
                if not any(r["type"] in ("SEMVER", "ECOSYSTEM") for r in ranges):
                    unknown = True
                continue
            active, uncertain = False, False
            for event in version_range["events"]:
                if "introduced" in event:
                    number = (
                        1
                        if event["introduced"] == "0"
                        else compare(version, event["introduced"], ecosystem)
                    )
                    if number is None:
                        uncertain = True
                    else:
                        active = number >= 0
                else:
                    end = event.get("fixed", event.get("limit", event.get("last_affected")))
                    if end is None:
                        uncertain = True
                        continue
                    number = compare(version, end, ecosystem)
                    if number is None:
                        uncertain = True
                        continue
                    included = number <= 0 if "last_affected" in event else number < 0
                    if active and included:
                        return "unknown" if uncertain else "affected"
                    active = False
            if active and not uncertain:
                return "affected"
            unknown = unknown or uncertain
        if not affected.get("versions") and not ranges:
            unknown = True
    return "unknown" if unknown else "not-affected"
