# mcp_server.py
import os

# from graphql_mcp import GraphQLMCPServer  # or: 
from mcp_graphql import GraphQLMCPServer

GRAPHQL_ENDPOINT = os.getenv("GRAPHQL_API_ENDPOINT", "http://127.0.0.1:8000/graphql")

server = GraphQLMCPServer(
    endpoint=GRAPHQL_ENDPOINT,
    # If you use auth later:
    # headers={"Authorization": f"Bearer {os.getenv('GRAPHQL_API_TOKEN', '')}"},
    whitelist=["cves", "cve", "containerAssets", "containerAsset"],
)

if __name__ == "__main__":
    # Run as MCP over stdio
    server.run_stdio()