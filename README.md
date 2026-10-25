# SecuLens for Python

[English](README.md) | [日本語](README.jp.md)

Independent Python implementation of SecuLens: assess SPDX / CycloneDX JSON SBOMs against OSV records, apply SPDX license-expression policies, review Python ASTs, and produce customer-facing Word and JSON reports. Python 3.10+; no Node.js or Trivy runtime required.

Version 1.1.0 provides the assessment features described below. Full SAST and legal compliance determinations are outside its scope. A vulnerability match is evidence from the supplied advisory snapshot; a security AST finding is a review candidate.

## Interactive wizard

Run `seculens` with no arguments to start interactive setup. English is the default: press Enter at the language prompt, or type `ja` for Japanese. Use `seculens wizard --lang ja` to open Japanese setup directly.

```sh
seculens
# or
seculens wizard --lang ja
```

Choose an existing SBOM assessment or SBOM generation, then supply the requested paths and options. Assessment asks for a local OSV snapshot or explicit OSV fetching, an optional license policy and source directory, customer / target / preparer, report style, output directory and findings exit policy. Customer report layout is the wizard default. Review the settings and confirm to start. EOF or choosing `n` at the final prompt cancels; Ctrl+C interrupts. OSV fetching sends package names and ecosystems; the wizard displays this before execution.


## Install

Install from [PyPI](https://pypi.org/project/seculens/):

```sh
python -m pip install seculens
seculens
```

Wheels are also available from [GitHub releases](https://github.com/masahiroid/seculens-python/releases). For development:

```sh
python -m venv .venv
# Activate your virtual environment, then:
pip install -e '.[dev]'
seculens --version
```

## Quick start (offline)

```sh
seculens scan examples/cyclonedx.json --db examples/database.json \
  --policy examples/policy.json --source examples \
  --customer "Sample Customer" --lang ja --output reports/sample
```

`examples/database.json` is synthetic demonstration data, not a production vulnerability database. Outputs are `report.docx`, `report.json`, `sbom.json`, and `database.json`. Japanese Word reports embed the bundled Noto Sans JP font under the SIL Open Font License.

Download current OSV candidates explicitly:

```sh
seculens scan bom.json --fetch-osv --policy examples/policy.json --output reports/live
```

Only package names and ecosystems are sent to `api.osv.dev`; matching is performed locally. Use `--db` for offline assessment. Pagination, withdrawn records, version ranges, advisory aliases, unsupported identities and incomplete ranges are accounted for. `no-match` never means vulnerability-free. Evidence hashes identify the exact SBOM and database text used.

## Generate SBOMs

Install [Syft](https://github.com/anchore/syft) separately, then:

```sh
seculens sbom ./project --format cyclonedx --output bom.cdx.json
seculens sbom ./project --format spdx --output bom.spdx.json
```

`--syft /path/to/syft` selects an executable. SecuLens validates its output. Existing CycloneDX 1.4–1.7 JSON or SPDX 2.2/2.3 JSON can also be imported directly. Package URLs identify npm, PyPI and Packagist dependencies regardless of which language implementation runs the assessment. SPDX 3 and XML are not supported yet.

## License policy

```json
{"allow": ["MIT", "Apache-2.0", "BSD-3-Clause"], "deny": ["GPL-3.0-only"]}
```

SPDX `AND` requires all branches to be allowed; `OR` accepts an allowed option. `WITH` exceptions require an exact policy entry. Unrecognized or missing expressions require review. This evaluates the configured policy, not every legal obligation or regulatory framework.

## Python analysis

`--source` parses `.py` files without importing or executing them. Rules review `eval` / `exec`, OS shell calls, `subprocess` with literal `shell=True`, pickle deserialization and YAML loading without an explicit safe loader. Complexity review triggers above cyclomatic 10 or nesting 4. Imports and aliases are recognized syntactically; shadowing, dynamic aliases, data flow and exploitability are not resolved. Syntax errors become coverage findings. Virtual environments, dependency/build directories and symlinks are skipped. JS/TS source analysis belongs to the [TypeScript implementation](https://github.com/masahiroid/seculens); PHP source analysis is available in the [independent PHP implementation](https://github.com/masahiroid/seculens-php).

## Exit status and API

- `0`: assessment completed (findings may exist).
- `1`: `--fail-on-findings` and a vulnerability, denied license or security review candidate exists.
- `2`: incomplete coverage or an operational error; status 1 takes precedence when requested.

```python
from seculens import scan_sbom, write_word_report

report = scan_sbom(sbom_text, records, policy={"allow": ["MIT"]}, customer="Customer")
write_word_report(report, "report.docx", language="ja")
```

Schema `1.1` is shared with the TypeScript implementation. Advisory matching supports PyPI PEP 440, npm SemVer and stable numeric Composer versions / SemVer prereleases; Composer branches and Git commit ranges can remain unassessed. Customer-specific risk prioritization, reachability, container/OS scanning and full SAST are future work. Reports do not claim those checks were performed.

## Validation

```sh
pytest
ruff check .
ruff format --check .
pip-audit
python -m build
python -m twine check dist/*
```

See [security policy](SECURITY.md). Apache-2.0 code; bundled Japanese font is SIL OFL. [NOTICE](NOTICE) identifies third-party assets.

## Customer report mode

Add `--report-style customer` to generate a formal Word report with a dedicated cover, executive summary, severity colors, a prioritized findings register, numbered details, component coverage tables, evidence hashes and page numbers. Existing standard layout remains available with `--report-style standard` (the default).

```sh
seculens scan bom.json --db database.json --policy policy.json \
  --customer "Customer Company" --target "Customer Web Service" \
  --issuer "Security Assessment Team" --lang ja \
  --report-style customer --output reports/customer
```

`--target` supplies a human-readable system name; it defaults to the SBOM filename. `--issuer` supplies the cover's preparer and document author. Both are optional. The report ID incorporates the SBOM hash, DB hash and assessment timestamp. Finding numbers link the register to details; code/license review statuses are separate from vulnerability severity.

Severity colors: Critical / High red, Medium amber, Low blue, None green, Unrated gray. Labels accompany colors for accessibility. Vulnerability counts consolidate aliases per component; category counts include review candidates. CVSS zero / None is a severity band, not proof of absence of vulnerabilities.

Severity comes from validated CVSS 3.0/3.1 base vectors or recognized `database_specific.severity` labels. Package-specific OSV `affected.severity` overrides global vectors for that affected entry. Alias consolidation preserves all provenance and displays the highest supported severity; when sources disagree, the underlying labels/vectors and scores remain available in JSON. CVSS 2/4 vectors and malformed vectors are not calculated. Without other usable metadata these stay Unrated. No severity is inferred from advisory wording, AST review candidates or licenses.

Report JSON schema 1.1 adds optional vulnerability `severity` (level, optional base score, and source record IDs / field paths / raw values) and optional CLI `sourceAnalysis` execution metadata. Presentation sorting does not alter the assessment JSON. Word contains concise severity attribution; full original metadata and references stay in JSON. This mode changes presentation and adds severity evidence, not the vulnerability matching criteria.

Scoring reference: https://www.first.org/cvss/v3.1/specification-document
OSV field reference: https://ossf.github.io/osv-schema/

```python
write_word_report(
    report, "customer.docx", language="ja", style="customer", issuer="Assessment Team"
)
```
