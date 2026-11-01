import json
from pathlib import Path

import pytest

from seculens.matcher import compare, match_record

CASES = json.loads((Path(__file__).parent / "fixtures/composer-versions.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=lambda c: f"{c['a']} vs {c['b']}")
def test_composer_versions(case):
    assert compare(case["a"], case["b"], "Packagist") == case["expected"]
    if case["expected"] is not None:
        assert compare(case["b"], case["a"], "Packagist") == -case["expected"]


def test_packagist_ranges_use_composer_stability_order():
    record = {
        "id": "X",
        "affected": [
            {
                "package": {"name": "acme/lib", "ecosystem": "Packagist"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0-RC1"}]}
                ],
            }
        ],
    }

    def at(version):
        return match_record(
            {"name": "acme/lib", "ecosystem": "Packagist", "version": version}, record
        )

    assert at("2.0.0-beta3") == "affected"
    assert at("2.0.0-RC1") == "not-affected"
    assert at("1.9.9.1") == "affected"
    assert at("2.x-dev") == "unknown"
