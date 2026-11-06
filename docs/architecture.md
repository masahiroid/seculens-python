# Assessment contract

The Python implementation owns SBOM normalization, ecosystem version comparisons, OSV candidate downloads and local matching, SPDX license policy evaluation, Python AST rules, and Word generation. It does not invoke TypeScript or Trivy. Syft is optional and used only for SBOM generation.

`report.json` uses SecuLens schema 1.2: tool/version, creation time, customer, target, SBOM and database hashes, normalized components/dependencies/warnings, per-component checks, findings and limitations. Fixed input text, advisory records and `created_at` produce deterministic assessment JSON. Word font embedding uses a generated GUID, so DOCX bytes are not deterministic.

`validation.py` validates SBOM and report JSON offline against the schemas bundled in `src/seculens/schemas/` (shared byte-for-byte with the TypeScript and PHP repositories). It never resolves remote references.

Advisory IDs and aliases are merged transitively per component. No CVSS severity is inferred from match count. `cvss4.py` scores CVSS 4.0 vectors, and `priority.py` ranks findings from the policy `context` without changing severity. Unknown package identities, unsupported version syntax and unevaluable candidate ranges are reported as incomplete coverage. Syntax errors are also coverage findings. Static review candidates do not establish exploitability.

Offline mode saves the exact supplied SBOM and database text. OSV mode saves the fetched candidate records and performs version comparison locally, rather than trusting version-filtered remote matches. SPDX license obligations beyond the configured allow/deny policy are not determined.

See the README customer report mode section for severity evidence and layout options.
