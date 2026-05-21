#!/usr/bin/env python3
import json
import sys
import uuid
from typing import Any, Dict, Optional
import http.client
from urllib.parse import urlparse

GRAPHQL_ENDPOINT = "http://127.0.0.1:8000/graphql"

def call_graphql(query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    url = urlparse(GRAPHQL_ENDPOINT)
    conn = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=30)
    body = json.dumps({"query": query, "variables": variables or {}})
    headers = {"Content-Type": "application/json"}
    conn.request("POST", url.path or "/graphql", body, headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    if resp.status != 200:
        raise RuntimeError(f"GraphQL error {resp.status}: {data!r}")
    payload = json.loads(data.decode("utf-8"))
    if "errors" in payload:
        raise RuntimeError(f"GraphQL errors: {payload['errors']}")
    return payload.get("data", {})

def send_response(id: Any, result: Any = None, error: Any = None):
    response = {"jsonrpc": "2.0", "id": id}
    if error is not None:
        response["error"] = error
    else:
        response["result"] = result
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = req.get("method")
        req_id = req.get("id")

        # Basic MCP-like JSON-RPC handling
        if method == "initialize":
            # Minimal capabilities and tool metadata
            result = {
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "cve-graphql-mcp",
                    "version": "0.1.0",
                },
                "capabilities": {
                    "tools": {}
                },
            }
            send_response(req_id, result=result)

        elif method == "tools/list":
            # Define tools and their JSON-schema-ish params
            tools = [
                {
                    "name": "cves",
                    "description": "List CVEs with optional filters",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "severity": {"type": "string"},
                            "limit": {"type": "integer", "default": 20},
                            "created_after": {"type": "string"},
                            "created_before": {"type": "string"},
                        },
                    },
                },
                {
                    "name": "cve",
                    "description": "Get a single CVE by id",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                        },
                        "required": ["id"],
                    },
                },
                {
                    "name": "containerAssets",
                    "description": "List container assets with optional filters",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "publicly_exposed": {"type": "boolean"},
                            "runs_as_root": {"type": "boolean"},
                            "limit": {"type": "integer", "default": 20},
                        },
                    },
                },
                {
                    "name": "containerAsset",
                    "description": "Get one container asset by id",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer"},
                        },
                        "required": ["id"],
                    },
                },
            ]
            send_response(req_id, result={"tools": tools})

        elif method == "tools/call":
            params = req.get("params") or {}
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}
            try:
                if tool_name == "cves":
                    q = """
                    query Cves($severity: String, $limit: Int!, $createdAfter: DateTime, $createdBefore: DateTime) {
                      cves(severity: $severity, limit: $limit, createdAfter: $createdAfter, createdBefore: $createdBefore) {
                        id
                        summary
                        severity
                        cvssScore
                        publishedAt
                      }
                    }
                    """
                    vars = {
                        "severity": arguments.get("severity"),
                        "limit": arguments.get("limit", 20),
                        "createdAfter": arguments.get("created_after"),
                        "createdBefore": arguments.get("created_before"),
                    }
                    data = call_graphql(q, vars)
                    send_response(req_id, result={"content": data})

                elif tool_name == "cve":
                    q = """
                    query Cve($id: String!) {
                      cve(id: $id) {
                        id
                        summary
                        severity
                        cvssScore
                        publishedAt
                        references
                      }
                    }
                    """
                    vars = {"id": arguments["id"]}
                    data = call_graphql(q, vars)
                    send_response(req_id, result={"content": data})

                elif tool_name == "containerAssets":
                    q = """
                    query ContainerAssets($publiclyExposed: Boolean, $runsAsRoot: Boolean, $limit: Int!) {
                      containerAssets(publiclyExposed: $publiclyExposed, runsAsRoot: $runsAsRoot, limit: $limit) {
                        id
                        name
                        image
                        publiclyExposed
                        runsAsRoot
                        cves {
                          id
                          severity
                          cvssScore
                        }
                      }
                    }
                    """
                    vars = {
                        "publiclyExposed": arguments.get("publicly_exposed"),
                        "runsAsRoot": arguments.get("runs_as_root"),
                        "limit": arguments.get("limit", 20),
                    }
                    data = call_graphql(q, vars)
                    send_response(req_id, result={"content": data})

                elif tool_name == "containerAsset":
                    q = """
                    query ContainerAsset($id: Int!) {
                      containerAsset(id: $id) {
                        id
                        name
                        image
                        publiclyExposed
                        runsAsRoot
                        cves {
                          id
                          severity
                          cvssScore
                        }
                      }
                    }
                    """
                    vars = {"id": arguments["id"]}
                    data = call_graphql(q, vars)
                    send_response(req_id, result={"content": data})

                else:
                    send_response(
                        req_id,
                        error={"code": -32601, "message": f"Unknown tool {tool_name}"},
                    )
            except Exception as e:
                send_response(
                    req_id,
                    error={
                        "code": -32000,
                        "message": f"Tool execution error: {e}",
                    },
                )

        else:
            # Unknown method
            send_response(
                req_id,
                error={"code": -32601, "message": f"Unknown method {method}"},
            )

if __name__ == "__main__":
    main()