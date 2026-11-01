# Bundled JSON schemas

Official upstream schemas are vendored without modification. `sources.json` records their source URLs and SHA-256 digests. CycloneDX schemas (including JSF and its SPDX license enumeration) are Apache-2.0; SPDX document schemas are from the SPDX project under CC-BY-3.0. Full license texts are included here. SecuLens report schema is Apache-2.0.

`report-1.1.schema.json` defines the serialized report contract across all three implementations. Its `$id` is an identifier, not a download endpoint. Schema validation checks structure and declared formats, not vulnerability correctness, SPDX license expression semantics, completeness of an SBOM, or all specification prose requirements. Duplicate component IDs and missing graph endpoints are handled by normalization separately.

To update upstream schemas, fetch the exact reviewed upstream revision, retain licenses, update `sources.json` hashes, copy the complete directory to the other implementations, and run every validation fixture in each language. Do not load schemas or references named by untrusted input. Runtime resolution uses only this bundled directory.
