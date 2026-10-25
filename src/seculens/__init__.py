"""SecuLens Python implementation; no JavaScript runtime dependency."""

from .analysis import analyze, check_lifecycle_scripts
from .core import scan_sbom, sha256
from .database import fetch_database, validate_database
from .integrity import check_lockfile_integrity, check_package_cool_off
from .licenses import evaluate_license
from .matcher import match_record
from .mcp import MCP_TOOLS, handle_mcp_request, run_mcp_server
from .sbom import compute_dependency_depths, parse_sbom
from .word import write_word_report

__version__ = "1.1.0"
__all__ = [
    "scan_sbom",
    "sha256",
    "parse_sbom",
    "compute_dependency_depths",
    "match_record",
    "evaluate_license",
    "fetch_database",
    "validate_database",
    "analyze",
    "check_lifecycle_scripts",
    "check_lockfile_integrity",
    "check_package_cool_off",
    "MCP_TOOLS",
    "handle_mcp_request",
    "run_mcp_server",
    "__version__",
    "write_word_report",
]
