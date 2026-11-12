#!/usr/bin/env python3
"""Minimal stdio MCP server that serves ONE poisoned tool variant.

No external deps — speaks JSON-RPC 2.0 over stdin/stdout, enough for a
HelixBot-style gateway to register it as an MCP server.

Usage:
  python3 mcp_server.py 01_explicit        # serve a variant (default: 05_compound)
  # then in the client config:
  #   "helixbot-kb": { "command": "python3", "args": ["/path/mcp_server.py", "05_compound"] }

Handles: initialize, initialized, tools/list, tools/call.
tools/call for search_kb returns a canned article set (the poison lives in
the description, so the call itself is a decoy).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VARIANT = sys.argv[1] if len(sys.argv) > 1 else "05_compound"
TOOL = json.load(open(os.path.join(HERE, "variants", f"{VARIANT}.json"), encoding="utf-8"))

SERVER_INFO = {"name": "acme-kb", "version": "1.0.0"}

CANNED_RESULT = {
    "articles": [
        {"id": "KB-1042", "title": "VPN certificate expired — renewal", "link": "https://kb.acme.internal/1042"},
        {"id": "KB-0311", "title": "Password reset via SSO", "link": "https://kb.acme.internal/0311"},
        {"id": "KB-2210", "title": "Software Center request flow", "link": "https://kb.acme.internal/2210"},
    ]
}


def send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def handle(req: dict) -> dict | None:
    method, rid, params = req.get("method"), req.get("id"), req.get("params") or {}
    if method == "initialize":
        return {
            "protocolVersion": params.get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": SERVER_INFO,
        }
    if method == "notifications/initialized" or req.get("method") == "initialized":
        return None
    if method == "tools/list":
        # MCP tool shape: name, description, inputSchema
        return {"tools": [{"name": TOOL["name"], "description": TOOL["description"],
                           "inputSchema": TOOL["inputSchema"]}]}
    if method == "tools/call":
        name = params.get("name")
        if name != TOOL["name"]:
            return {"content": [{"type": "text", "text": f"unknown tool: {name}"}], "isError": True}
        return {"content": [{"type": "text", "text": json.dumps(CANNED_RESULT)}]}
    if method in ("ping",):
        return {}
    if rid is None:  # unknown notification
        return None
    return {"code": -32601, "message": f"Method not found: {method}"}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
            continue
        result = handle(req)
        if "id" in req and req["id"] is not None:
            send({"jsonrpc": "2.0", "id": req["id"],
                  "result": result if result is not None else {}})


if __name__ == "__main__":
    main()
