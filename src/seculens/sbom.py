"""Normalize supported JSON SBOM fields without executing source code."""

from __future__ import annotations

from typing import Any

from packageurl import PackageURL


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _identity(purl: str | None) -> dict[str, str]:
    if not purl:
        return {}
    try:
        parsed = PackageURL.from_string(purl)
    except (ValueError, TypeError):
        return {}
    result = {"name": f"{parsed.namespace}/{parsed.name}" if parsed.namespace else parsed.name}
    ecosystem = {"npm": "npm", "pypi": "PyPI", "composer": "Packagist"}.get(parsed.type)
    if ecosystem:
        result["ecosystem"] = ecosystem
    if parsed.version:
        result["version"] = parsed.version
    return result


def parse_sbom(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("SBOM must be a JSON object")
    components: list[dict[str, Any]] = []
    dependencies: list[dict[str, str]] = []
    warnings: list[str] = []
    if data.get("bomFormat") == "CycloneDX":
        fmt = "CycloneDX"
        version = data.get("specVersion")
        if version not in ("1.4", "1.5", "1.6", "1.7"):
            raise ValueError(f"Unsupported CycloneDX version: {version}")
        if not isinstance(data.get("components", []), list):
            raise ValueError("CycloneDX components must be an array")

        def collect(items: list[Any], prefix: str) -> None:
            for index, item in enumerate(items):
                if not isinstance(item, dict) or not _text(item.get("name")):
                    raise ValueError("Component name is required")
                component: dict[str, Any] = {
                    "id": item.get("bom-ref") or f"{prefix}{index}",
                    "name": f"{item['group']}/{item['name']}"
                    if item.get("group")
                    else item["name"],
                    "licenses": [],
                }
                if _text(item.get("version")):
                    component["version"] = item["version"]
                if _text(item.get("purl")):
                    component["purl"] = item["purl"]
                    component.update(_identity(item["purl"]))
                if isinstance(item.get("hashes"), list):
                    component["hashes"] = [
                        {"alg": str(h["alg"]), "content": str(h["content"])}
                        for h in item["hashes"]
                        if isinstance(h, dict) and _text(h.get("alg")) and _text(h.get("content"))
                    ]
                for entry in item.get("licenses", []):
                    if not isinstance(entry, dict):
                        raise ValueError("License entries must be objects")
                    license_data = entry.get("license") or {}
                    expression = (
                        entry.get("expression")
                        or license_data.get("id")
                        or license_data.get("name")
                    )
                    if _text(expression):
                        component["licenses"].append(expression)
                components.append(component)
                if isinstance(item.get("components"), list):
                    collect(item["components"], f"{prefix}{index}/")

        collect(data.get("components", []), "component-")
        for entry in data.get("dependencies", []):
            for target in entry.get("dependsOn", []):
                dependencies.append({"from": entry["ref"], "to": target})
    elif _text(data.get("spdxVersion")):
        fmt = "SPDX"
        version = data["spdxVersion"]
        if version not in ("SPDX-2.2", "SPDX-2.3"):
            raise ValueError(f"Unsupported SPDX version: {version}. SPDX 3 is not supported yet.")
        if not isinstance(data.get("packages"), list):
            raise ValueError("SPDX packages must be an array")
        for index, item in enumerate(data["packages"]):
            if not isinstance(item, dict) or not _text(item.get("name")):
                raise ValueError("Package name is required")
            license_value = item.get("licenseConcluded")
            if not license_value or license_value == "NOASSERTION":
                license_value = item.get("licenseDeclared")
            component = {
                "id": item.get("SPDXID") or f"package-{index}",
                "name": item["name"],
                "licenses": [license_value] if _text(license_value) else [],
            }
            if _text(item.get("versionInfo")):
                component["version"] = item["versionInfo"]
            purl = next(
                (
                    r.get("referenceLocator")
                    for r in item.get("externalRefs", [])
                    if r.get("referenceType") == "purl"
                ),
                None,
            )
            if _text(purl):
                component["purl"] = purl
                component.update(_identity(purl))
            if isinstance(item.get("checksums"), list):
                component["hashes"] = [
                    {"alg": str(cs["algorithm"]), "content": str(cs["checksumValue"])}
                    for cs in item["checksums"]
                    if isinstance(cs, dict) and _text(cs.get("algorithm")) and _text(cs.get("checksumValue"))
                ]
            components.append(component)
        for entry in data.get("relationships", []):
            if entry.get("relationshipType") == "DEPENDS_ON":
                dependencies.append(
                    {"from": entry["spdxElementId"], "to": entry["relatedSpdxElement"]}
                )
            elif entry.get("relationshipType") == "DEPENDENCY_OF":
                dependencies.append(
                    {"from": entry["relatedSpdxElement"], "to": entry["spdxElementId"]}
                )
    else:
        raise ValueError("Expected SPDX JSON or CycloneDX JSON")
    ids: set[str] = set()
    for component in components:
        if not _text(component["id"]):
            raise ValueError("Component ID must be a string")
        if component["id"] in ids:
            raise ValueError(f"Duplicate component ID: {component['id']}")
        ids.add(component["id"])
        if component.get("purl") and not _identity(component["purl"]).get("name"):
            warnings.append(f"Invalid purl: {component['id']}")
    for edge in dependencies:
        if not all(_text(edge.get(key)) for key in ("from", "to")):
            raise ValueError("Dependency endpoints must be strings")
        if edge["from"] not in ids or edge["to"] not in ids:
            warnings.append(
                f"Dependency endpoint not in component list: {edge['from']} -> {edge['to']}"
            )
    compute_dependency_depths(components, dependencies)
    return {
        "format": fmt,
        "version": version,
        "components": components,
        "dependencies": dependencies,
        "warnings": warnings,
    }


def compute_dependency_depths(
    components: list[dict[str, Any]], dependencies: list[dict[str, str]]
) -> None:
    if not dependencies:
        return
    adj: dict[str, list[str]] = {c["id"]: [] for c in components}
    in_degree: dict[str, int] = {c["id"]: 0 for c in components}
    for dep in dependencies:
        frm, to = dep.get("from", ""), dep.get("to", "")
        if frm in adj:
            adj[frm].append(to)
        if to in in_degree:
            in_degree[to] += 1

    roots = [cid for cid, deg in in_degree.items() if deg == 0 and adj.get(cid)]
    depths: dict[str, int] = {}
    queue: list[tuple[str, int]] = []
    for r in roots:
        for child in adj.get(r, []):
            if child not in depths:
                depths[child] = 1
                queue.append((child, 1))

    while queue:
        cid, depth = queue.pop(0)
        for nxt in adj.get(cid, []):
            if nxt not in depths or depths[nxt] > depth + 1:
                depths[nxt] = depth + 1
                queue.append((nxt, depth + 1))

    for c in components:
        if c["id"] in depths:
            c["depth"] = depths[c["id"]]
