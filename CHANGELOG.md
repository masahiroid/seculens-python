# Changelog

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
