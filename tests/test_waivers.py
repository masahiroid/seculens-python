import json
from pathlib import Path

import pytest

from seculens import apply_waivers, validate_document, validate_waivers
from seculens.cli import main
from seculens.mcp import handle_mcp_request

ROOT = Path(__file__).parents[1]
FIXTURE = json.loads((ROOT / "tests/fixtures/waivers.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda c: c["name"])
def test_shared_waiver_cases(case):
    assert apply_waivers(case["findings"], case["waivers"], case["date"]) == case["expected"]


def test_valid_waiver_files():
    for data in FIXTURE["valid"]:
        assert validate_waivers(data) == data
        assert validate_document(data, "waivers")["valid"] is True


def test_invalid_waiver_files():
    for data in FIXTURE["invalid"]:
        with pytest.raises(ValueError, match="Waiver"):
            validate_waivers(data)
        assert validate_document(data, "waivers")["valid"] is False, data


def test_invalid_evaluation_date():
    with pytest.raises(ValueError, match="Waiver"):
        apply_waivers([], [], "2026-13-01")


def _waiver_file(rule_id, expires):
    return {
        "schemaVersion": "1.0",
        "waivers": [
            {
                "ruleId": rule_id,
                "justification": "Demo package is not shipped",
                "approvedBy": "Security team",
                "expires": expires,
            }
        ],
    }


def test_cli_waiver_keeps_finding_and_clears_exit_code(tmp_path):
    waivers = tmp_path / "waivers.json"
    waivers.write_text(json.dumps(_waiver_file("SECULENS-DEMO-001", "2999-12-31")))
    out = tmp_path / "out"
    args = [
        "scan",
        str(ROOT / "examples/cyclonedx.json"),
        "--db",
        str(ROOT / "examples/database.json"),
        "--waivers",
        str(waivers),
        "--fail-on-findings",
        "-o",
        str(out),
    ]
    assert main(args) == 0
    report = json.loads((out / "report.json").read_text())
    finding = next(f for f in report["findings"] if f["category"] == "vulnerability")
    assert finding["status"] == "affected"
    assert finding["waiver"]["source"] == "waivers[0]"
    assert report["schemaVersion"] == "1.3"
    assert validate_document(report, "report")["valid"] is True
    older = {**report, "schemaVersion": "1.2"}
    assert validate_document(older, "report")["valid"] is False
    older["findings"] = [{k: v for k, v in f.items() if k != "waiver"} for f in report["findings"]]
    assert validate_document(older, "report")["valid"] is True
    waivers.write_text(json.dumps(_waiver_file("SECULENS-DEMO-001", "2000-01-01")))
    assert main(args) == 1
    expired = json.loads((out / "report.json").read_text())
    assert any(f["ruleId"] == "WAIVER-EXPIRED" for f in expired["findings"])


def test_cli_rejects_invalid_waiver_file(tmp_path, capsys):
    waivers = tmp_path / "waivers.json"
    waivers.write_text(json.dumps(_waiver_file("X", "2027-02-30")))
    code = main(
        [
            "scan",
            str(ROOT / "examples/cyclonedx.json"),
            "--db",
            str(ROOT / "examples/database.json"),
            "--waivers",
            str(waivers),
            "-o",
            str(tmp_path / "out"),
        ]
    )
    assert code == 2
    assert "expires" in capsys.readouterr().err


def test_mcp_scan_applies_waivers():
    def call(arguments):
        return handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "seculens_scan", "arguments": arguments},
            }
        )["result"]

    result = call(
        {
            "sbomPath": str(ROOT / "examples/cyclonedx.json"),
            "dbPath": str(ROOT / "examples/database.json"),
            "waivers": _waiver_file("SECULENS-DEMO-001", "2999-12-31"),
        }
    )
    body = json.loads(result["content"][0]["text"])
    assert body["summary"]["waived"] >= 1
    assert body["summary"]["affectedVulnerabilities"] == 0
    bad = call({"sbomPath": str(ROOT / "examples/cyclonedx.json"), "waivers": {"waivers": []}})
    assert bad["isError"] is True
