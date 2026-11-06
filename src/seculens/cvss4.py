"""CVSS v4.0 scoring per FIRST's specification, using its published MacroVector tables."""

from __future__ import annotations

import json
import math
from functools import lru_cache
from pathlib import Path
from typing import Any

METRICS = {
    "AV": "NALP",
    "AC": "LH",
    "AT": "NP",
    "PR": "NLH",
    "UI": "NPA",
    "VC": "HLN",
    "VI": "HLN",
    "VA": "HLN",
    "SC": "HLN",
    "SI": "HLN",
    "SA": "HLN",
    "E": "XAPU",
    "CR": "XHML",
    "IR": "XHML",
    "AR": "XHML",
    "MAV": "XNALP",
    "MAC": "XLH",
    "MAT": "XNP",
    "MPR": "XNLH",
    "MUI": "XNPA",
    "MVC": "XHLN",
    "MVI": "XHLN",
    "MVA": "XHLN",
    "MSC": "XHLN",
    "MSI": "XSHLN",
    "MSA": "XSHLN",
    "S": "XNP",
    "AU": "XNY",
    "R": "XAUI",
    "V": "XDC",
    "RE": "XLMH",
    "U": ("X", "Clear", "Green", "Amber", "Red"),
}
ORDER = list(METRICS)
BASE = ORDER[:11]
LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}


@lru_cache(maxsize=1)
def _tables() -> dict[str, Any]:
    path = Path(__file__).parent / "schemas" / "cvss-v4-data.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _parse(vector: Any) -> dict[str, str] | None:
    if not isinstance(vector, str) or not vector.startswith("CVSS:4.0/"):
        return None
    metrics: dict[str, str] = {}
    position = -1
    for token in vector.split("/")[1:]:
        pair = token.split(":")
        if len(pair) != 2 or pair[0] not in METRICS:
            return None
        index = ORDER.index(pair[0])
        if index <= position or not pair[1] or pair[1] not in METRICS[pair[0]]:
            return None
        position = index
        metrics[pair[0]] = pair[1]
    return metrics if all(key in metrics for key in BASE) else None


def _effective(metrics: dict[str, str], key: str) -> str:
    """Threat and requirement metrics default to worst case; modified metrics override base."""
    selected = metrics.get(key, "X")
    if key == "E" and selected == "X":
        return "A"
    if key in ("CR", "IR", "AR") and selected == "X":
        return "H"
    modified = metrics.get(f"M{key}")
    return modified if modified is not None and modified != "X" else selected


def cvss4_score(vector: Any) -> float | None:
    """Return the score, or None when the vector is not a valid CVSS v4.0 vector."""
    metrics = _parse(vector)
    if metrics is None:
        return None

    def get(key: str) -> str:
        return _effective(metrics, key)

    if all(get(key) == "N" for key in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0
    tables = _tables()
    lookup, composed, severity = tables["lookup"], tables["maxComposed"], tables["maxSeverity"]
    av, pr, ui = get("AV"), get("PR"), get("UI")
    if av == "N" and pr == "N" and ui == "N":
        eq1 = 0
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = 1
    else:
        eq1 = 2
    eq2 = 0 if get("AC") == "L" and get("AT") == "N" else 1
    vc, vi, va = get("VC"), get("VI"), get("VA")
    eq3 = 0 if vc == "H" and vi == "H" else 1 if "H" in (vc, vi, va) else 2
    if get("MSI") == "S" or get("MSA") == "S":
        eq4 = 0
    else:
        eq4 = 1 if "H" in (get("SC"), get("SI"), get("SA")) else 2
    eq5 = {"A": 0, "P": 1, "U": 2}[get("E")]
    high = (get("CR") == "H" and vc == "H") or (get("IR") == "H" and vi == "H")
    eq6 = 0 if high or (get("AR") == "H" and va == "H") else 1

    def at(*parts: int) -> float | None:
        return lookup.get("".join(str(part) for part in parts))

    value = at(eq1, eq2, eq3, eq4, eq5, eq6)
    if eq3 == 0 and eq6 == 0:
        left = at(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
        right = at(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
        lower_eq3_eq6 = left if left is not None and right is not None and left > right else right
    elif eq3 == 1 and eq6 == 0:
        lower_eq3_eq6 = at(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
    elif eq3 == 2:
        lower_eq3_eq6 = None
    else:
        lower_eq3_eq6 = at(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    lower = [
        at(eq1 + 1, eq2, eq3, eq4, eq5, eq6),
        at(eq1, eq2 + 1, eq3, eq4, eq5, eq6),
        lower_eq3_eq6,
        at(eq1, eq2, eq3, eq4 + 1, eq5, eq6),
        at(eq1, eq2, eq3, eq4, eq5 + 1, eq6),
    ]
    distance: dict[str, float] = {}
    # The first highest-severity vector that is not below the scored vector sets the distances.
    candidates = (
        a + b + c + d + e
        for a in composed["eq1"][str(eq1)]
        for b in composed["eq2"][str(eq2)]
        for c in composed["eq3"][str(eq3)][str(eq6)]
        for d in composed["eq4"][str(eq4)]
        for e in composed["eq5"][str(eq5)]
    )
    for candidate in candidates:
        highest = dict(token.split(":") for token in candidate.split("/") if token)
        distance = {key: LEVELS[key][get(key)] - LEVELS[key][highest[key]] for key in LEVELS}
        if all(item >= 0 for item in distance.values()):
            break
    d = distance
    step = 0.1
    current = [
        d["AV"] + d["PR"] + d["UI"],
        d["AC"] + d["AT"],
        d["VC"] + d["VI"] + d["VA"] + d["CR"] + d["IR"] + d["AR"],
        d["SC"] + d["SI"] + d["SA"],
        0,
    ]
    depth = [
        severity["eq1"][str(eq1)] * step,
        severity["eq2"][str(eq2)] * step,
        severity["eq3eq6"][str(eq3)][str(eq6)] * step,
        severity["eq4"][str(eq4)] * step,
        1,
    ]
    total = 0.0
    existing = 0
    for index, score in enumerate(lower):
        if score is None:
            continue
        existing += 1
        total += (value - score) * (current[index] / depth[index])
    result = min(max(value - (total / existing if existing else 0), 0), 10)
    return math.floor(result * 10 + 0.5) / 10
