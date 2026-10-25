"""Lockfile integrity verification and package release age (cool-off) inspection."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import urllib.request


def check_lockfile_integrity(
    directory: str | Path, sbom: dict[str, Any]
) -> list[dict[str, Any]]:
    root = Path(directory).resolve()
    findings: list[dict[str, Any]] = []

    # 1. npm package-lock.json
    npm_lock = root / "package-lock.json"
    if npm_lock.is_file():
        try:
            lock = json.loads(npm_lock.read_text(encoding="utf-8"))
            packages = lock.get("packages", {})
            sbom_hashes: dict[str, list[dict[str, str]]] = {}
            for c in sbom.get("components", []):
                name = c.get("name")
                ver = c.get("version", "")
                if name and c.get("hashes"):
                    sbom_hashes[f"{name}@{ver}"] = c["hashes"]

            for pkg_key, pkg_val in packages.items():
                if not pkg_key or not isinstance(pkg_val, dict):
                    continue
                pkg_name = pkg_key.split("node_modules/")[-1]
                version = pkg_val.get("version", "")
                resolved = pkg_val.get("resolved", "")
                integrity = pkg_val.get("integrity", "")

                if isinstance(resolved, str) and resolved.startswith("http://"):
                    findings.append({
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
                    })

                key = f"{pkg_name}@{version}"
                if key in sbom_hashes and integrity and "-" in integrity:
                    alg, val = integrity.split("-", 1)
                    matched = False
                    for h in sbom_hashes[key]:
                        h_alg = h.get("alg", "").lower().replace("-", "").replace("_", "")
                        h_content = h.get("content", "")
                        if h_alg == alg.lower():
                            try:
                                h_b64 = base64.b64encode(bytes.fromhex(h_content)).decode()
                            except ValueError:
                                h_b64 = h_content
                            if h_content == val or h_b64 == val:
                                matched = True
                                break
                    if not matched and sbom_hashes[key]:
                        findings.append({
                            "category": "security",
                            "ruleId": "SC-INTEGRITY-MISMATCH",
                            "subject": pkg_name,
                            "status": "review",
                            "summary": f"Lockfile integrity hash mismatch for {pkg_name}@{version}",
                            "evidence": f'lockfile: "{integrity}"; SBOM: {sbom_hashes[key]}',
                            "recommendation": (
                                "Investigate possible package tampering or lockfile poisoning "
                                "before installing or deploying."
                            ),
                            "file": "package-lock.json",
                        })
        except Exception:
            pass

    # 2. composer.lock
    composer_lock = root / "composer.lock"
    if composer_lock.is_file():
        try:
            lock = json.loads(composer_lock.read_text(encoding="utf-8"))
            pkgs = lock.get("packages", []) + lock.get("packages-dev", [])
            for p in pkgs:
                if not isinstance(p, dict):
                    continue
                name = p.get("name", "")
                dist_url = p.get("dist", {}).get("url", "")
                if isinstance(dist_url, str) and dist_url.startswith("http://"):
                    findings.append({
                        "category": "security",
                        "ruleId": "SC-INSECURE-REGISTRY-URL",
                        "subject": name,
                        "status": "review",
                        "summary": f"Insecure HTTP download URL in composer.lock: {name}",
                        "evidence": f'dist.url: "{dist_url}"',
                        "recommendation": "Use secure HTTPS package sources to avoid tampering.",
                        "file": "composer.lock",
                    })
        except Exception:
            pass

    return findings


def check_package_cool_off(
    components: list[dict[str, Any]],
    min_days: int = 7,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    if now is None:
        now = datetime.now(timezone.utc)
    findings: list[dict[str, Any]] = []

    pypi_components = [
        c for c in components if c.get("ecosystem") == "PyPI" and c.get("name") and c.get("version")
    ]
    for c in pypi_components:
        name = c["name"]
        version = c["version"]
        try:
            url = f"https://pypi.org/pypi/{name}/json"
            req = urllib.request.Request(url, headers={"User-Agent": "SecuLens-Audit"})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                releases = data.get("releases", {}).get(version, [])
                if releases and "upload_time_iso_8601" in releases[0]:
                    iso_time = releases[0]["upload_time_iso_8601"]
                    pub_date = datetime.fromisoformat(iso_time.replace("Z", "+00:00"))
                    diff_days = (now - pub_date).days
                    if 0 <= diff_days < min_days:
                        findings.append({
                            "category": "security",
                            "ruleId": "SC-PACKAGE-AGE-UNVERIFIED",
                            "subject": f"{name}@{version}",
                            "status": "review",
                            "summary": f"Package version was released recently ({diff_days} day(s) ago)",
                            "evidence": (
                                f"Published on {iso_time} ({diff_days} days ago; "
                                f"cool-off threshold={min_days} days)"
                            ),
                            "recommendation": (
                                "Allow a cool-off period before upgrading in production "
                                "to guard against compromised zero-day releases."
                            ),
                        })
        except Exception:
            pass

    return findings

