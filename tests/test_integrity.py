import json

from seculens import (
    check_lockfile_integrity,
    compute_dependency_depths,
)


def test_compute_dependency_depths():
    components = [
        {"id": "root-app", "name": "app"},
        {"id": "pkg-a", "name": "a"},
        {"id": "pkg-b", "name": "b"},
        {"id": "pkg-c", "name": "c"},
    ]
    dependencies = [
        {"from": "root-app", "to": "pkg-a"},
        {"from": "pkg-a", "to": "pkg-b"},
        {"from": "pkg-b", "to": "pkg-c"},
    ]
    compute_dependency_depths(components, dependencies)

    assert next(c for c in components if c["id"] == "pkg-a").get("depth") == 1
    assert next(c for c in components if c["id"] == "pkg-b").get("depth") == 2
    assert next(c for c in components if c["id"] == "pkg-c").get("depth") == 3


def test_lockfile_integrity_insecure_url(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "node_modules/insecure-lib": {
                        "version": "1.0.0",
                        "resolved": "http://evil-mirror.org/insecure-lib-1.0.0.tgz",
                    }
                }
            }
        )
    )
    sbom = {
        "components": [{"id": "c1", "name": "insecure-lib", "version": "1.0.0"}],
    }
    findings = check_lockfile_integrity(tmp_path, sbom)
    assert len(findings) == 1
    assert findings[0]["ruleId"] == "SC-INSECURE-REGISTRY-URL"


def test_lockfile_integrity_mismatch(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "node_modules/tampered-pkg": {
                        "version": "2.0.0",
                        "integrity": "sha512-LOCKFILE_FAKE_HASH_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
                    }
                }
            }
        )
    )
    sbom = {
        "components": [
            {
                "id": "c1",
                "name": "tampered-pkg",
                "version": "2.0.0",
                "hashes": [
                    {
                        "alg": "SHA-512",
                        "content": "SBOM_GENUINE_HASH_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==",
                    }
                ],
            }
        ],
    }
    findings = check_lockfile_integrity(tmp_path, sbom)
    assert len(findings) == 1
    assert findings[0]["ruleId"] == "SC-INTEGRITY-MISMATCH"


# Shared with the TypeScript and PHP implementations (tests/fixtures/supply-chain.json).
from datetime import datetime  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

from seculens import (  # noqa: E402
    check_package_cool_off,
    cool_off_findings,
    expand_packagist_versions,
    fetch_release_dates,
    parse_cool_off_days,
)

SHARED = json.loads(
    (Path(__file__).parent / "fixtures/supply-chain.json").read_text(encoding="utf-8")
)


@pytest.mark.parametrize("case", SHARED["integrity"], ids=lambda c: c["name"])
def test_shared_integrity_fixture(case, tmp_path):
    for name, content in case["files"].items():
        (tmp_path / name).write_text(content if isinstance(content, str) else json.dumps(content))
    assert (
        check_lockfile_integrity(tmp_path, {"components": case["components"]}) == case["expected"]
    )


def test_lockfile_integrity_missing_directory(tmp_path):
    assert check_lockfile_integrity(tmp_path / "missing", {"components": []}) == []


def _now(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def test_shared_cool_off_fixture():
    f = SHARED["coolOff"]
    assert (
        cool_off_findings(f["components"], f["published"], f["minDays"], _now(f["now"]))
        == f["expected"]
    )


def test_shared_cool_off_day_limits():
    for value in SHARED["coolOff"]["validDays"]:
        assert parse_cool_off_days(value) == int(value)
    for value in SHARED["coolOff"]["invalidDays"]:
        with pytest.raises(ValueError, match="Cool-off must be a whole number"):
            parse_cool_off_days(value)


def test_check_package_cool_off_uses_injected_lookup():
    f = SHARED["coolOff"]
    seen = []

    def lookup(components):
        seen.append(len(components))
        return f["published"]

    assert check_package_cool_off(f["components"], 7, _now(f["now"]), lookup) == f["expected"]
    assert seen == [len(f["components"])]


def test_fetch_release_dates_queries_each_registry_once():
    urls = []

    def get_json(url):
        urls.append(url)
        if "missing" in url:
            return None
        if url.startswith("https://registry.npmjs.org/"):
            return {"time": {"1.0.0": "2026-11-14T00:00:00Z", "1.1.0": "2026-11-15T00:00:00Z"}}
        if url.startswith("https://pypi.org/"):
            return {
                "urls": [
                    {"upload_time_iso_8601": "2026-11-16T02:00:00Z"},
                    {"upload_time_iso_8601": "2026-11-16T01:00:00Z"},
                ]
            }
        return {
            "packages": {
                "acme/lib": [
                    {"version": "v1.2.0", "time": "2026-11-13T00:00:00+00:00"},
                    {"version": "v1.1.0"},
                ]
            }
        }

    def c(name, version, ecosystem):
        return {"name": name, "version": version, "ecosystem": ecosystem}

    dates = fetch_release_dates(
        [
            c("@scope/pkg", "1.0.0", "npm"),
            c("@scope/pkg", "1.1.0", "npm"),
            c("Requests", "2.40.0", "PyPI"),
            c("acme/lib", "1.2.0", "Packagist"),
            c("acme/lib", "1.1.0", "Packagist"),
            c("missing", "1.0.0", "npm"),
            c("lib", "1.0.0", "Maven"),
        ],
        get_json,
    )
    assert dates == {
        "npm": {
            "@scope/pkg@1.0.0": "2026-11-14T00:00:00Z",
            "@scope/pkg@1.1.0": "2026-11-15T00:00:00Z",
        },
        "PyPI": {"Requests@2.40.0": "2026-11-16T01:00:00Z"},
        "Packagist": {
            "acme/lib@1.2.0": "2026-11-13T00:00:00+00:00",
            "acme/lib@1.1.0": "2026-11-13T00:00:00+00:00",
        },
    }
    assert urls == [
        "https://registry.npmjs.org/@scope%2Fpkg",
        "https://pypi.org/pypi/Requests/2.40.0/json",
        "https://repo.packagist.org/p2/acme/lib.json",
        "https://registry.npmjs.org/missing",
    ]


def test_fetch_release_dates_network_failure_is_unknown(monkeypatch):
    import urllib.request

    def offline(*_args, **_kwargs):
        raise OSError("offline")

    monkeypatch.setattr(urllib.request, "urlopen", offline)
    assert fetch_release_dates([{"name": "a", "version": "1.0.0", "ecosystem": "npm"}]) == {
        "npm": {},
        "PyPI": {},
        "Packagist": {},
    }


def test_expand_packagist_versions_honours_unset():
    assert expand_packagist_versions(
        [
            {"version": "2.0.0", "time": "t2", "license": ["MIT"]},
            {"version": "1.0.0", "license": "__unset"},
        ]
    ) == [
        {"version": "2.0.0", "time": "t2", "license": ["MIT"]},
        {"version": "1.0.0", "time": "t2"},
    ]
