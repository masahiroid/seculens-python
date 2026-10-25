from pathlib import Path
from seculens.mcp import handle_mcp_request, MCP_TOOLS

ROOT = Path(__file__).resolve().parents[1]


def test_mcp_initialize():
    res = handle_mcp_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "test-client"},
        },
    })
    assert res["id"] == 1
    assert res["result"]["protocolVersion"] == "2024-11-05"
    assert res["result"]["serverInfo"]["name"] == "seculens-python"
    assert "tools" in res["result"]["capabilities"]


def test_mcp_tools_list():
    res = handle_mcp_request({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
    })
    assert res["id"] == 2
    names = [t["name"] for t in res["result"]["tools"]]
    assert "seculens_scan" in names
    assert "seculens_analyze" in names
    assert "seculens_check_license" in names
    assert "seculens_generate_report" in names


def test_mcp_check_license():
    res = handle_mcp_request({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "seculens_check_license",
            "arguments": {
                "expression": "MIT OR Apache-2.0",
                "allow": ["MIT"],
            },
        },
    })
    assert res["id"] == 3
    assert res["result"]["isError"] is False
    assert '"status": "allowed"' in res["result"]["content"][0]["text"]


def test_mcp_scan_offline():
    res = handle_mcp_request({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "seculens_scan",
            "arguments": {
                "sbomPath": str(ROOT / "examples/cyclonedx.json"),
                "dbPath": str(ROOT / "examples/database.json"),
                "policy": {"allow": ["MIT", "Apache-2.0"]},
            },
        },
    })
    assert res["id"] == 4
    assert res["result"]["isError"] is False
    assert '"components":' in res["result"]["content"][0]["text"]

