"""Minimal MCP stdio server. One JSON-RPC message per line.

Tools default to the offline scan so an agent does not spend model calls
unless it passes use_llm.
"""

from __future__ import annotations

import json
import sys
from typing import Any, TextIO

from auditsift import __version__
from auditsift.errors import AuditError
from auditsift.pipeline import audit
from auditsift.render import render

PROTOCOL = "2024-11-05"
SERVER_INFO = {"name": "auditsift", "version": __version__}

_PATH = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "description": "File or directory to read."},
        "diff": {
            "type": "string",
            "description": "Git ref. Only changed lines are reported.",
        },
    },
    "required": ["path"],
}

TOOLS = [
    {
        "name": "auditsift_map",
        "description": "Inventory languages, routes, manifests, and redacted secrets. Offline.",
        "inputSchema": _PATH,
    },
    {
        "name": "auditsift_scan",
        "description": "Run offline security rules and return the JSON report. No model calls.",
        "inputSchema": _PATH,
    },
    {
        "name": "auditsift_audit",
        "description": (
            "Map and scan, then optionally triage and verify with the configured models. use_llm defaults to false."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                **_PATH["properties"],
                "use_llm": {
                    "type": "boolean",
                    "description": "When true, call triage and verify if an API key is set.",
                },
                "fail_on": {
                    "type": "string",
                    "description": "Severity that should be treated as a failed audit.",
                },
            },
            "required": ["path"],
        },
    },
]


def serve(instream: TextIO | None = None, outstream: TextIO | None = None) -> None:
    instream = instream or sys.stdin
    outstream = outstream or sys.stdout
    print("auditsift mcp ready", file=sys.stderr)
    for line in instream:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = dispatch(message)
        if response is None:
            continue
        outstream.write(json.dumps(response) + "\n")
        outstream.flush()


def dispatch(message: dict[str, Any]) -> dict[str, Any] | None:
    method = message.get("method")
    msg_id = message.get("id")
    if isinstance(method, str) and method.startswith("notifications/"):
        return None
    if method == "initialize":
        params = message.get("params") or {}
        version = params.get("protocolVersion") or PROTOCOL
        return _ok(
            msg_id,
            {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
            },
        )
    if method == "ping":
        return _ok(msg_id, {})
    if method == "tools/list":
        return _ok(msg_id, {"tools": TOOLS})
    if method == "tools/call":
        return _call(msg_id, message.get("params") or {})
    if msg_id is None:
        return None
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"unknown method {method}"},
    }


def _call(msg_id: Any, params: dict[str, Any]) -> dict[str, Any]:
    name = params.get("name")
    arguments = params.get("arguments") or {}
    try:
        if name == "auditsift_map":
            report = audit(arguments["path"], diff=arguments.get("diff"), use_llm=False)
            text = json.dumps(report.inventory, indent=2)
        elif name == "auditsift_scan":
            report = audit(arguments["path"], diff=arguments.get("diff"), use_llm=False)
            text = render(report, "json")
        elif name == "auditsift_audit":
            report = audit(
                arguments["path"],
                diff=arguments.get("diff"),
                use_llm=bool(arguments.get("use_llm")),
            )
            text = render(report, "json")
        else:
            raise AuditError(f"unknown tool {name}")
        return _ok(
            msg_id,
            {"content": [{"type": "text", "text": text}], "isError": False},
        )
    except (AuditError, KeyError, OSError, TypeError) as exc:
        return _ok(
            msg_id,
            {"content": [{"type": "text", "text": str(exc)}], "isError": True},
        )


def _ok(msg_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}
