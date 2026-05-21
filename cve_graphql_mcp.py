# cve_graphql_mcp.py
import os
from typing import Any, Dict, Optional

import httpx
from fastmcp import FastMCP, Context, tool

GRAPHQL_ENDPOINT = os.getenv(
    "GRAPHQL_API_ENDPOINT",
    "http://127.0.0.1:8000/graphql",
)

mcp = FastMCP(
    name="cve-graphql",
    version="0.1.0",
    description="MCP server exposing CVE and container GraphQL queries",
)

async def call_graphql(query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            GRAPHQL_ENDPOINT,
            json={"query": query, "variables": variables or {}},
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()
        if "errors" in data:
            raise RuntimeError(f"GraphQL errors: {data['errors']}")
        return data["data"]

@tool(mcp, name="cves", description="List CVEs with optional filters")
async def cves_tool(
    ctx: Context,
    severity: Optional[str] = None,
    limit: int = 20,
    created_after: Optional[str] = None,
    created_before: Optional[str] = None,
) -> Dict[str, Any]:
    query = """
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
    variables = {
      "severity": severity,
      "limit": limit,
      "createdAfter": created_after,
      "createdBefore": created_before,
    }
    return await call_graphql(query, variables)

@tool(mcp, name="cve", description="Get a single CVE by ID")
async def cve_tool(
    ctx: Context,
    id: str,
) -> Dict[str, Any]:
    query = """
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
    variables = {"id": id}
    return await call_graphql(query, variables)

@tool(mcp, name="containerAssets", description="List container assets with optional filters")
async def container_assets_tool(
    ctx: Context,
    publicly_exposed: Optional[bool] = None,
    runs_as_root: Optional[bool] = None,
    limit: int = 20,
) -> Dict[str, Any]:
    query = """
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
    variables = {
      "publiclyExposed": publicly_exposed,
      "runsAsRoot": runs_as_root,
      "limit": limit,
    }
    return await call_graphql(query, variables)

@tool(mcp, name="containerAsset", description="Get one container asset by ID")
async def container_asset_tool(
    ctx: Context,
    id: int,
) -> Dict[str, Any]:
    query = """
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
    variables = {"id": id}
    return await call_graphql(query, variables)

if __name__ == "__main__":
    mcp.run()