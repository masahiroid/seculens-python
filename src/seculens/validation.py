"""Offline validation against bundled official SBOM and SecuLens report schemas."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource

SCHEMAS = Path(__file__).parent / "schemas"


@lru_cache(maxsize=7)
def _validator(name: str) -> Draft7Validator:
    registry = Registry()
    for filename in ("spdx.schema.json", "jsf-0.82.schema.json", "cryptography-defs.schema.json"):
        schema = json.loads((SCHEMAS / filename).read_text(encoding="utf-8"))
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    schema = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
    return Draft7Validator(schema, registry=registry, format_checker=FormatChecker())


def validate_document(data: Any, kind: str = "sbom") -> dict[str, Any]:
    if kind == "report":
        name = "report-1.1.schema.json"
    elif kind != "sbom":
        raise ValueError("Kind must be sbom or report")
    elif (
        isinstance(data, dict)
        and data.get("bomFormat") == "CycloneDX"
        and data.get("specVersion") in ("1.4", "1.5", "1.6", "1.7")
    ):
        name = f"bom-{data['specVersion']}.schema.json"
    elif isinstance(data, dict) and data.get("spdxVersion") in ("SPDX-2.2", "SPDX-2.3"):
        name = f"spdx-{data['spdxVersion'][5:]}.schema.json"
    else:
        return {
            "valid": False,
            "schema": "",
            "errors": [{"path": "", "message": "Expected supported SPDX or CycloneDX version"}],
        }
    error = next(_validator(name).iter_errors(data), None)
    errors = (
        []
        if error is None
        else [
            {
                "path": "".join(
                    "/" + str(part).replace("~", "~0").replace("/", "~1")
                    for part in error.absolute_path
                ),
                "message": error.message,
            }
        ]
    )
    return {"valid": not errors, "schema": name, "errors": errors}
