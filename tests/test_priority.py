import hashlib
import json
from pathlib import Path

import pytest

from seculens import component_priority, cvss4_score, scan_sbom, validate_context, validate_document

FIXTURES = Path(__file__).parent / "fixtures"
VECTORS = json.loads((FIXTURES / "cvss4-vectors.json").read_text(encoding="utf-8"))
PRIORITY = json.loads((FIXTURES / "priority.json").read_text(encoding="utf-8"))


def test_cvss4_published_and_generated_vectors():
    for case in VECTORS["published"] + VECTORS["generated"]:
        assert cvss4_score(case["vector"]) == case["score"], case["vector"]


@pytest.mark.parametrize("vector", [*VECTORS["invalid"], None])
def test_cvss4_rejects_invalid_vectors(vector):
    assert cvss4_score(vector) is None


def test_cvss4_every_base_combination_matches_shared_digest():
    keys = list(VECTORS["baseMetrics"])
    digest = hashlib.sha256()
    count = 0

    def walk(index, parts):
        nonlocal count
        if index == len(keys):
            vector = "CVSS:4.0/" + "/".join(parts)
            digest.update(f"{vector} {cvss4_score(vector):.1f}\n".encode())
            count += 1
            return
        for value in VECTORS["baseMetrics"][keys[index]]:
            walk(index + 1, [*parts, f"{keys[index]}:{value}"])

    walk(0, [])
    assert count == VECTORS["baseVectors"]["count"]
    assert digest.hexdigest() == VECTORS["baseVectors"]["sha256"]


@pytest.mark.parametrize("case", PRIORITY["cases"], ids=lambda c: c["name"])
def test_priority_cases(case):
    assert (
        component_priority(case["severity"], case["component"], case["context"]) == case["expected"]
    )


@pytest.mark.parametrize("context", PRIORITY["invalidContexts"], ids=json.dumps)
def test_priority_rejects_invalid_context(context):
    with pytest.raises(ValueError, match="Policy"):
        validate_context(context)


def _scan(policy):
    scan = PRIORITY["scan"]
    return scan_sbom(json.dumps(scan["sbom"]), scan["records"], policy=policy)


def _vulnerability(report):
    return next(f for f in report["findings"] if f["category"] == "vulnerability")


def test_scan_scores_cvss4_and_prioritizes_against_schema():
    scan = PRIORITY["scan"]
    report = _scan(scan["policy"])
    finding = _vulnerability(report)
    assert finding["severity"]["level"] == scan["expected"]["severity"]["level"]
    assert finding["severity"]["score"] == scan["expected"]["severity"]["score"]
    assert finding["priority"] == scan["expected"]["priority"]
    assert validate_document(report, "report")["valid"]
    assert "priority" not in _vulnerability(_scan({}))
    with pytest.raises(ValueError, match="Policy"):
        _scan({"context": {"foo": 1}})


def test_validation_keeps_accepting_schema_1_1_reports():
    report = _scan(PRIORITY["scan"]["policy"])
    report["schemaVersion"] = "1.1"
    result = validate_document(report, "report")
    assert result["schema"] == "report-1.1.schema.json"
    assert not result["valid"]
    for finding in report["findings"]:
        finding.pop("priority", None)
    assert validate_document(report, "report")["valid"]
