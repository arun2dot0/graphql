import json
from typing import Optional
from mcp.server.fastmcp import FastMCP

# Import your existing schema object from your schema.py file
from schema import schema

# Initialize FastMCP Server
mcp = FastMCP("Vulnerability-Scanner")

@mcp.tool()
def get_cves(
    severity: Optional[str] = None, 
    limit: int = 20, 
    published_after: Optional[str] = None, 
    published_before: Optional[str] = None
) -> str:
    """
    Fetch a list of CVEs with optional filters for severity, limits, and date ranges.
    Dates should be provided in ISO format (YYYY-MM-DDTHH:MM:SS).
    """
    gql_query = """
    query GetCVEs($severity: String, $limit: Int, $after: DateTime, $before: DateTime) {
        cves(severity: $severity, limit: $limit, publishedAfter: $after, publishedBefore: $before) {
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
        "after": published_after,
        "before": published_before
    }
    
    result = schema.execute_sync(gql_query, variable_values=variables)
    if result.errors:
        return f"GraphQL Errors: {json.dumps([str(e) for e in result.errors])}"
        
    return json.dumps(result.data.get("cves", []), default=str)


@mcp.tool()
def get_cve_details(cve_id: str) -> str:
    """
    Retrieve comprehensive details, description, references, and raw data for a specific CVE ID.
    """
    gql_query = """
    query GetCVEDetails($id: String!) {
        cve(id: $id) {
            id
            summary
            severity
            cvssScore
            publishedAt
            updatedAt
            description
            references
            rawData
        }
    }
    """
    
    result = schema.execute_sync(gql_query, variable_values={"id": cve_id})
    if result.errors:
        return f"GraphQL Errors: {json.dumps([str(e) for e in result.errors])}"
        
    return json.dumps(result.data.get("cve"), default=str)


@mcp.tool()
def get_container_assets(
    publicly_exposed: Optional[bool] = None, 
    runs_as_root: Optional[bool] = None, 
    limit: int = 20
) -> str:
    """
    List container assets with filters to check if they run as root or are publicly exposed.
    Returns the basic asset info and attached CVE IDs.
    """
    gql_query = """
    query GetContainers($publiclyExposed: Boolean, $runsAsRoot: Boolean, $limit: Int) {
        containerAssets(publiclyExposed: $publiclyExposed, runsAsRoot: $runsAsRoot, limit: $limit) {
            id
            name
            image
            registry
            environment
            namespace
            publiclyExposed
            runsAsRoot
            cves {
                id
                severity
            }
        }
    }
    """
    
    variables = {
        "publiclyExposed": publicly_exposed,
        "runsAsRoot": runs_as_root,
        "limit": limit
    }
    
    result = schema.execute_sync(gql_query, variable_values=variables)
    if result.errors:
        return f"GraphQL Errors: {json.dumps([str(e) for e in result.errors])}"
        
    return json.dumps(result.data.get("containerAssets", []), default=str)


@mcp.tool()
def get_container_asset_details(asset_id: int) -> str:
    """
    Get all information for a specific container asset using its integer ID, including its full list of vulnerabilities.
    """
    gql_query = """
    query GetContainerDetails($id: Int!) {
        containerAsset(id: $id) {
            id
            name
            image
            registry
            environment
            namespace
            serviceName
            publiclyExposed
            runsAsRoot
            createdAt
            updatedAt
            cves {
                id
                summary
                severity
                cvssScore
            }
        }
    }
    """
    
    result = schema.execute_sync(gql_query, variable_values={"id": asset_id})
    if result.errors:
        return f"GraphQL Errors: {json.dumps([str(e) for e in result.errors])}"
        
    return json.dumps(result.data.get("containerAsset"), default=str)


if __name__ == "__main__":
    mcp.run(transport="stdio")
