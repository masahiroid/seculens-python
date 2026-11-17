"""Lockfile integrity verification and package release age (cool-off) inspection."""

from __future__ import annotations

import base64
import json
import math
import re
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ReleaseDates = dict[str, dict[str, str]]
COOL_OFF_MAX_DAYS = 3650
_COOL_OFF_ECOSYSTEMS = ("npm", "PyPI", "Packagist")
_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$", re.IGNORECASE
)
_HEX = re.compile(r"^(?:[0-9a-fA-F]{2})+$")


def _read_lock(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _base64_digest(content: str) -> str:
    """Hex digests are compared as base64, the encoding npm uses; anything else as written."""
    return base64.b64encode(bytes.fromhex(content)).decode() if _HEX.match(content) else content


def _normalize_alg(alg: str) -> str:
    return alg.lower().replace("-", "").replace("_", "")


def _compact(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def check_lockfile_integrity(directory: str | Path, sbom: dict[str, Any]) -> list[dict[str, Any]]:
    """Check package-lock.json and composer.lock in ``directory``; missing or unparseable lockfiles are skipped."""
    root = Path(directory).resolve()
    findings: list[dict[str, Any]] = []

    npm_lock = _read_lock(root / "package-lock.json")
    if npm_lock is not None:
        sbom_hashes: dict[str, list[dict[str, str]]] = {}
        for c in sbom.get("components", []):
            if c.get("name") and c.get("hashes"):
                sbom_hashes[f"{c['name']}@{c.get('version') or ''}"] = c["hashes"]
        packages = npm_lock.get("packages")
        for pkg_key, pkg_val in (packages if isinstance(packages, dict) else {}).items():
            if not pkg_key or not isinstance(pkg_val, dict):
                continue
            pkg_name = pkg_key.split("node_modules/")[-1]
            version = pkg_val.get("version") if isinstance(pkg_val.get("version"), str) else ""
            resolved = pkg_val.get("resolved")
            integrity = pkg_val.get("integrity")

            if isinstance(resolved, str) and resolved.startswith("http://"):
                findings.append(
                    {
                        "category": "security",
                        "ruleId": "SC-INSECURE-REGISTRY-URL",
                        "subject": pkg_name,
                        "status": "review",
                        "summary": f"Insecure HTTP package resolution URL: {pkg_name}",
                        "evidence": f'resolved: "{resolved}"',
                        "recommendation": (
                            "Replace HTTP package sources with secure HTTPS registries "
                            "to prevent man-in-the-middle attacks."
                        ),
                        "file": "package-lock.json",
                    }
                )

            hashes = sbom_hashes.get(f"{pkg_name}@{version}")
            if not hashes or not isinstance(integrity, str) or "-" not in integrity:
                continue
            alg, value = integrity.split("-", 1)
            matched = any(
                _normalize_alg(h["alg"]) == alg.lower()
                and (h["content"] == value or _base64_digest(h["content"]) == value)
                for h in hashes
            )
            if not matched:
                listed = [{"alg": h["alg"], "content": h["content"]} for h in hashes]
                findings.append(
                    {
                        "category": "security",
                        "ruleId": "SC-INTEGRITY-MISMATCH",
                        "subject": pkg_name,
                        "status": "review",
                        "summary": f"Lockfile integrity hash mismatch for {pkg_name}@{version}",
                        "evidence": f'lockfile: "{integrity}"; SBOM hashes: {_compact(listed)}',
                        "recommendation": (
                            "Investigate possible package tampering or lockfile poisoning "
                            "before installing or deploying."
                        ),
                        "file": "package-lock.json",
                    }
                )

    composer_lock = _read_lock(root / "composer.lock")
    if composer_lock is not None:

        def items(value: Any) -> list[Any]:
            return value if isinstance(value, list) else []

        for p in items(composer_lock.get("packages")) + items(composer_lock.get("packages-dev")):
            if not isinstance(p, dict):
                continue
            name = p.get("name") if isinstance(p.get("name"), str) else ""
            dist = p.get("dist")
            dist_url = dist.get("url") if isinstance(dist, dict) else None
            if isinstance(dist_url, str) and dist_url.startswith("http://"):
                findings.append(
                    {
                        "category": "security",
                        "ruleId": "SC-INSECURE-REGISTRY-URL",
                        "subject": name,
                        "status": "review",
                        "summary": f"Insecure HTTP download URL in composer.lock: {name}",
                        "evidence": f'dist.url: "{dist_url}"',
                        "recommendation": (
                            "Use secure HTTPS package sources to avoid tampering during download."
                        ),
                        "file": "composer.lock",
                    }
                )

    return findings


def parse_cool_off_days(value: Any) -> int:
    """Accept a whole number of days from 1 to 3650, given as an int or a string of digits."""
    if isinstance(value, int) and not isinstance(value, bool):
        text = str(value)
    elif isinstance(value, float) and value.is_integer():
        text = str(int(value))
    elif isinstance(value, str):
        text = value
    else:
        text = ""
    days = int(text) if re.fullmatch(r"[0-9]+", text) else 0
    if not 1 <= days <= COOL_OFF_MAX_DAYS:
        raise ValueError(f"Cool-off must be a whole number of days from 1 to {COOL_OFF_MAX_DAYS}")
    return days


def _timestamp_ms(text: str) -> int | None:
    if not _TIMESTAMP.match(text):
        return None
    # Millisecond precision, matching the TypeScript and PHP implementations.
    trimmed = re.sub(r"(\.\d{3})\d+", r"\1", text)
    try:
        parsed = datetime.fromisoformat(re.sub(r"[zZ]$", "+00:00", trimmed))
    except ValueError:
        return None
    return math.floor(parsed.timestamp() * 1000 + 0.5) if parsed.tzinfo else None


def _cool_off_targets(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    targets = []
    for c in components:
        if (
            not c.get("name")
            or not c.get("version")
            or c.get("ecosystem") not in _COOL_OFF_ECOSYSTEMS
        ):
            continue
        key = f"{c['ecosystem']}|{c['name']}@{c['version']}"
        if key not in seen:
            seen.add(key)
            targets.append(c)
    return targets


def cool_off_findings(
    components: list[dict[str, Any]], published: ReleaseDates, min_days: int, now: datetime
) -> list[dict[str, Any]]:
    """Pure cool-off evaluation: one finding per npm, PyPI or Packagist release younger than ``min_days``."""
    now_ms = math.floor(now.timestamp() * 1000 + 0.5)
    findings: list[dict[str, Any]] = []
    for c in _cool_off_targets(components):
        time_str = (published.get(c["ecosystem"]) or {}).get(f"{c['name']}@{c['version']}")
        ms = _timestamp_ms(time_str) if isinstance(time_str, str) else None
        if ms is None:
            continue
        days = (now_ms - ms) // 86_400_000
        if days < 0 or days >= min_days:
            continue
        findings.append(
            {
                "category": "security",
                "ruleId": "SC-PACKAGE-AGE-UNVERIFIED",
                "subject": f"{c['name']}@{c['version']}",
                "status": "review",
                "summary": f"Package version was released recently ({days} day(s) ago)",
                "evidence": (
                    f"Published on {time_str} ({days} days ago; cool-off threshold={min_days} days)"
                ),
                "recommendation": (
                    "Allow a cool-off period before upgrading in production "
                    "to guard against compromised zero-day releases."
                ),
            }
        )
    return findings


def _get_json(url: str) -> Any:
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": "SecuLens"}
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - fixed https hosts
            return json.loads(response.read().decode("utf-8"))
    except Exception:
        return None


def expand_packagist_versions(versions: Any) -> list[dict[str, Any]]:
    """Expand Packagist's minified p2 version list, where each entry only lists fields that changed."""
    expanded: list[dict[str, Any]] = []
    previous: dict[str, Any] = {}
    for entry in versions if isinstance(versions, list) else []:
        if not isinstance(entry, dict):
            continue
        current = dict(previous)
        for key, value in entry.items():
            if value == "__unset":
                current.pop(key, None)
            else:
                current[key] = value
        expanded.append(current)
        previous = current
    return expanded


def fetch_release_dates(
    components: list[dict[str, Any]], get_json: Callable[[str], Any] = _get_json
) -> ReleaseDates:
    """Look up release timestamps from registry.npmjs.org, pypi.org and repo.packagist.org.

    Sends package names and versions only. Failed lookups are left out, so those components are not flagged.
    """
    dates: ReleaseDates = {"npm": {}, "PyPI": {}, "Packagist": {}}
    documents: dict[str, Any] = {}

    def once(url: str) -> Any:
        if url not in documents:
            documents[url] = get_json(url)
        return documents[url]

    for c in _cool_off_targets(components):
        name, version, ecosystem = c["name"], c["version"], c["ecosystem"]
        time: Any = None
        if ecosystem == "npm":
            doc = once("https://registry.npmjs.org/" + name.replace("/", "%2F", 1))
            if isinstance(doc, dict) and isinstance(doc.get("time"), dict):
                time = doc["time"].get(version)
        elif ecosystem == "PyPI":
            quote = urllib.parse.quote
            doc = once(
                f"https://pypi.org/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json"
            )
            urls = doc.get("urls") if isinstance(doc, dict) else None
            uploads = sorted(
                u["upload_time_iso_8601"]
                for u in (urls if isinstance(urls, list) else [])
                if isinstance(u, dict) and isinstance(u.get("upload_time_iso_8601"), str)
            )
            time = uploads[0] if uploads else None
        elif re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", name):
            doc = once(f"https://repo.packagist.org/p2/{name.lower()}.json")
            packages = doc.get("packages") if isinstance(doc, dict) else None
            listed = packages.get(name.lower()) if isinstance(packages, dict) else None

            def strip(v: str) -> str:
                return v[1:] if v[:1] in ("v", "V") else v

            for entry in expand_packagist_versions(listed):
                if isinstance(entry.get("version"), str) and strip(entry["version"]) == strip(
                    version
                ):
                    time = entry.get("time")
                    break
        if isinstance(time, str):
            dates[ecosystem][f"{name}@{version}"] = time
    return dates


def check_package_cool_off(
    components: list[dict[str, Any]],
    min_days: int = 7,
    now: datetime | None = None,
    lookup: Callable[[list[dict[str, Any]]], ReleaseDates] = fetch_release_dates,
) -> list[dict[str, Any]]:
    """Flag npm, PyPI and Packagist releases younger than ``min_days``."""
    return cool_off_findings(components, lookup(components), min_days, now or datetime.now(UTC))
