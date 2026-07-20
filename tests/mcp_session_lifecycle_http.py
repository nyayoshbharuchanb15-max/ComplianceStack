"""E2E P1 regression test: MCP streamable-http session lifecycle over HTTP.

Verifies (against http://localhost:3000/mcp):
  1) POST /mcp with no session id -> returns mcp-session-id header and 200
  2) Follow-up POST /mcp reusing that mcp-session-id -> 200/202 (NOT 404)
  3) DELETE /mcp with the session id -> 200
  4) After DELETE, POST /mcp with same id -> 404
"""
import json
import uuid
import httpx


MCP_URL = "http://localhost:3000/mcp"
HEADERS_JSON = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    # Omit Origin so validateOrigin passes (or use http://localhost)
}


def _init_payload():
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "regression-http", "version": "1.0.0"},
        },
    }


def _tools_list_payload():
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "tools/list",
        "params": {},
    }


def test_p1_session_lifecycle():
    with httpx.Client(timeout=15.0) as client:
        # 1) Create session
        r1 = client.post(MCP_URL, headers=HEADERS_JSON, content=json.dumps(_init_payload()))
        assert r1.status_code in (200, 202), f"init status={r1.status_code} body={r1.text[:400]}"
        session_id = r1.headers.get("mcp-session-id")
        assert session_id, f"missing mcp-session-id header. Headers={dict(r1.headers)}"
        print(f"[step1] session created id={session_id} status={r1.status_code}")

        # 2) Reuse session id — MUST NOT be 404 (the exact P1 bug)
        headers2 = dict(HEADERS_JSON, **{"mcp-session-id": session_id})
        r2 = client.post(MCP_URL, headers=headers2, content=json.dumps(_tools_list_payload()))
        assert r2.status_code in (200, 202), (
            f"P1 REGRESSION: reuse session returned {r2.status_code} body={r2.text[:400]}"
        )
        print(f"[step2] reuse ok status={r2.status_code}")

        # 3) DELETE session
        r3 = client.delete(MCP_URL, headers={"mcp-session-id": session_id})
        assert r3.status_code == 200, f"delete status={r3.status_code} body={r3.text[:400]}"
        print(f"[step3] delete status={r3.status_code}")

        # 4) After DELETE, reuse must 404
        r4 = client.post(MCP_URL, headers=headers2, content=json.dumps(_tools_list_payload()))
        assert r4.status_code == 404, f"expected 404 after delete, got {r4.status_code} body={r4.text[:400]}"
        print(f"[step4] post-delete correctly returned 404")


if __name__ == "__main__":
    test_p1_session_lifecycle()
    print("PASS")
