"""SecuLens Python implementation; no JavaScript runtime dependency."""

from .analysis import analyze, check_lifecycle_scripts
from .core import scan_sbom, sha256
from .cvss4 import cvss4_score
from .database import fetch_database, validate_database
from .integrity import (
    check_lockfile_integrity,
    check_package_cool_off,
    cool_off_findings,
    expand_packagist_versions,
    fetch_release_dates,
    parse_cool_off_days,
)
from .licenses import evaluate_license
from .matcher import match_record
from .mcp import MCP_TOOLS, handle_mcp_request, run_mcp_server
from .priority import component_priority, validate_context
from .sbom import compute_dependency_depths, parse_sbom
from .validation import validate_document
from .waivers import apply_waivers, is_calendar_date, unwaived, validate_waivers
from .word import write_word_report

__version__ = "1.7.0"
__all__ = [
    "scan_sbom",
    "validate_document",
    "sha256",
    "parse_sbom",
    "compute_dependency_depths",
    "match_record",
    "evaluate_license",
    "cvss4_score",
    "component_priority",
    "validate_context",
    "apply_waivers",
    "validate_waivers",
    "unwaived",
    "is_calendar_date",
    "fetch_database",
    "validate_database",
    "analyze",
    "check_lifecycle_scripts",
    "check_lockfile_integrity",
    "check_package_cool_off",
    "cool_off_findings",
    "expand_packagist_versions",
    "fetch_release_dates",
    "parse_cool_off_days",
    "MCP_TOOLS",
    "handle_mcp_request",
    "run_mcp_server",
    "__version__",
    "write_word_report",
]
