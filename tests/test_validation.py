import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from seculens import scan_sbom, validate_document

ROOT = Path(__file__).parent.parent
CASES = json.loads((Path(__file__).parent / "fixtures/validation.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_schema(case):
    result = validate_document(case["input"], case["kind"])
    assert result["valid"] == case["valid"], result
    assert (len(result["errors"]) == 0) == case["valid"]


def test_report():
    report = scan_sbom(
        (ROOT / "examples/cyclonedx.json").read_text(),
        json.loads((ROOT / "examples/database.json").read_text())["records"],
    )
    assert validate_document(report, "report")["valid"]
    bad = copy.deepcopy(report)
    bad["checks"][0]["status"] = "safe"
    assert not validate_document(bad, "report")["valid"]
    bad = copy.deepcopy(report)
    del bad["database"]["sha256"]
    assert not validate_document(bad, "report")["valid"]


def test_cli():
    for name, code, valid in [("cyclonedx", 0, True), ("policy", 2, False)]:
        result = subprocess.run(
            [sys.executable, "-m", "seculens", "validate", str(ROOT / f"examples/{name}.json")],
            capture_output=True,
            text=True,
        )
        assert result.returncode == code, result.stderr
        assert json.loads(result.stdout)["valid"] == valid
