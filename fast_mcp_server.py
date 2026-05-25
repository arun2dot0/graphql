import sys
import json
from typing import Optional
from mcp.server.fastmcp import FastMCP
from strawberry.extensions import SchemaExtension

# Import your schema
from schema import schema

mcp = FastMCP("Vulnerability-Scanner")

class ClaudeQueryLogger(SchemaExtension):
    """Custom Strawberry extension to capture exactly what Claude executes."""
    def on_execute(self):
        execution_context = self.execution_context
        
        print("\n" + "═"*60, file=sys.stderr)
        print("📥 RAW GRAPHQL RECEIVED FROM CLAUDE:", file=sys.stderr)
        print(execution_context.query, file=sys.stderr)
        if execution_context.variables:
            print(f"Variables: {json.dumps(execution_context.variables, indent=2)}", file=sys.stderr)
        print("═"*60 + "\n", file=sys.stderr)
        sys.stderr.flush()
        yield # Let the query execute

def execute_gql_with_logging(gql_query: str, variables: dict):
    # Simply execute—the schema-level extension will automatically intercept it
    result = schema.execute_sync(
        gql_query, 
        variable_values=variables
    )
    return result

@mcp.tool()
def get_cves(
    severity: Optional[str] = None, 
    limit: int = 20, 
    published_after: Optional[str] = None, 
    published_before: Optional[str] = None
) -> str:
    """Fetch a list of CVEs with optional filters for severity and limits."""
    gql_query = """
    query GetCVEs($severity: String, $limit: Int, $after: DateTime, $before: DateTime) {
        cves(severity: $severity, limit: $limit, publishedAfter: $after, publishedBefore: $before) {
            id
            summary
            severity
            cvssScore
        }
    }
    """
    variables = {"severity": severity, "limit": limit, "after": published_after, "before": published_before}
    result = execute_gql_with_logging(gql_query, variables)
    
    if result.errors:
        return f"GraphQL Errors: {json.dumps([str(e) for e in result.errors])}"
    return json.dumps(result.data.get("cves", []), default=str)

@mcp.tool()
def get_container_assets(
    publicly_exposed: Optional[bool] = None, 
    runs_as_root: Optional[bool] = None, 
    limit: int = 20
) -> str:
    """List container assets with filters to check if they run as root or are publicly exposed."""
    gql_query = """
    query GetContainers($publiclyExposed: Boolean, $runsAsRoot: Boolean, $limit: Int) {
        containerAssets(publiclyExposed: $publiclyExposed, runsAsRoot: $runsAsRoot, limit: $limit) {
            id
            name
            image
            publiclyExposed
            runsAsRoot
        }
    }
    """
    variables = {"publiclyExposed": publicly_exposed, "runsAsRoot": runs_as_root, "limit": limit}
    result = execute_gql_with_logging(gql_query, variables)
    
    if result.errors:
        return f"GraphQL Errors: {json.dumps([str(e) for e in result.errors])}"
    return json.dumps(result.data.get("containerAssets", []), default=str)

if __name__ == "__main__":
    mcp.run(transport="stdio")
