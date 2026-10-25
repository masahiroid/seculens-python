import json
from seculens import (
    compute_dependency_depths,
    check_lockfile_integrity,
    check_package_cool_off,
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
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "packages": {
            "node_modules/insecure-lib": {
                "version": "1.0.0",
                "resolved": "http://evil-mirror.org/insecure-lib-1.0.0.tgz",
            }
        }
    }))
    sbom = {
        "components": [{"id": "c1", "name": "insecure-lib", "version": "1.0.0"}],
    }
    findings = check_lockfile_integrity(tmp_path, sbom)
    assert len(findings) == 1
    assert findings[0]["ruleId"] == "SC-INSECURE-REGISTRY-URL"


def test_lockfile_integrity_mismatch(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "packages": {
            "node_modules/tampered-pkg": {
                "version": "2.0.0",
                "integrity": "sha512-LOCKFILE_FAKE_HASH_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
            }
        }
    }))
    sbom = {
        "components": [{
            "id": "c1",
            "name": "tampered-pkg",
            "version": "2.0.0",
            "hashes": [{"alg": "SHA-512", "content": "SBOM_GENUINE_HASH_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=="}],
        }],
    }
    findings = check_lockfile_integrity(tmp_path, sbom)
    assert len(findings) == 1
    assert findings[0]["ruleId"] == "SC-INTEGRITY-MISMATCH"

