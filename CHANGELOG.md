# Changelog

## 1.4.0

- Packagist matching now follows Composer version normalization: one to four numeric parts (e.g. `5.4.0.1`), build metadata ignored, and stability order dev < alpha < beta < RC < stable < patch (`a`, `b`, `pl`, `p` aliases and `-dev` suffixes included).
- Branch versions such as `dev-main` and `1.x-dev` remain unassessed, and other unrecognized Composer syntax is reported as unknown instead of guessed.
- Add a shared Composer version test corpus (`composer-versions.json`) used identically by the TypeScript, Python and PHP implementations.

## 1.3.0

- Require Python 3.11 or later. Python 3.10 reached end of life in October 2026; installers on 3.10 keep resolving 1.2.0.

## 1.2.0

- Add `seculens validate` for offline JSON Schema validation of SPDX 2.2/2.3 and CycloneDX 1.4–1.7 SBOMs and SecuLens reports (`--kind report`).
- Bundle the official upstream SPDX and CycloneDX schemas with source hashes and licenses, plus the cross-language report schema `report-1.1.schema.json`.
- Export `validateDocument` / `validate_document` / `Validation::validate` from the library API.

## 1.1.0

- Add lifecycle script detection (`SC-LIFECYCLE-SCRIPT`) in `package.json` and `package-lock.json`.
- Add supply-chain AST inspection rules for subprocess execution (`PY-CHILD-PROCESS`), environment variable access (`PY-PROCESS-ENV`), and sensitive path references (`PY-SENSITIVE-PATH`).
- Add Model Context Protocol (MCP) stdio server (`seculens mcp`) supporting Claude Desktop, Cursor, and other AI agents.
- Add lockfile integrity verification (`SC-INTEGRITY-MISMATCH`, `SC-INSECURE-REGISTRY-URL`) and release cool-off check (`--cool-off`).
- Add transitive dependency depth calculation in SBOM parsing.
- Add weekly Dependabot automated updates and pull request dependency review workflow.

## 1.0.0

- Align the Python, JavaScript/TypeScript and PHP release versions at 1.0.0.
- Includes SPDX/CycloneDX assessment, native vulnerability matching, license policies, language-native AST review, bilingual wizard and customer Word reports.
- Includes output file safety fixes from the preceding maintenance release.

## 0.3.2

- Protect report and SBOM output from destination symlink overwrite, and restrict new report file permissions.
- Bound external SBOM generation to five minutes.


## 0.3.1

- Move repository links and PyPI publisher configuration to the GitHub owner `masahiroid`.

## 0.3.0

- Start an interactive setup wizard when `seculens` is run without arguments.
- Add English (default) and Japanese prompts; propagate the selected language to Word reports.
- Collect assessment / SBOM generation settings, validate input paths, review settings and confirm before execution.
- Add `seculens wizard --lang en|ja` for direct language selection; preserve existing CLI commands.
- Cancel cleanly on EOF or declined execution; support Ctrl+C interruption.

## 0.2.0

- Add customer report mode: cover, severity summary, findings register, numbered details, component table and page numbers.
- Add human-readable target and preparer options.
- Add traceable advisory severity, validated CVSS 3.0/3.1 base scoring, package-specific score selection and conservative alias severity consolidation.
- Preserve unknown / unsupported severity as Unrated; distinguish AST/license review from vulnerability severity.
- Extend report JSON to schema 1.1 with severity provenance and optional source-analysis execution metadata.

## 0.1.0

Initial native implementation: SPDX / CycloneDX JSON import, OSV matching, license policies, source analysis and Word / JSON reports.
