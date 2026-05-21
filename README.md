
# CVE GraphQL API (Postgres + FastAPI + Strawberry)

This project is a minimal GraphQL API for querying CVE data stored in PostgreSQL.  
It uses FastAPI, Strawberry GraphQL, SQLAlchemy, and psycopg2.

## Features

- PostgreSQL schema `security` with a `cves` table for CVE records.
- Seed script to load sample CVEs.
- GraphQL API with:
  - `cves(severity, limit)` to list CVEs.
  - `cve(id)` to fetch a single CVE.
- Computed `references` field derived from `raw_data` JSON.

## Requirements

- Python 3.11+
- PostgreSQL (tested with 14+)
- pip / venv

## Setup

## 0. Use Podman to run postgres
```

podman volume create pg-data

podman run -d --name my-postgres -p 5432:5432 \
  -e POSTGRES_PASSWORD=vulns \
  -v /Users/aselvamani/code/pg-data:/var/lib/postgresql/data:Z \
  docker.io/library/postgres:16

podman exec -it my-postgres psql -U postgres 


```

### 1. Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\\Scripts\\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure the database

Create the `security` schema and tables in Postgres:

```sql
CREATE SCHEMA IF NOT EXISTS security;

CREATE TABLE IF NOT EXISTS security.cves (
    cve_id       TEXT PRIMARY KEY,
    summary      TEXT NOT NULL,
    severity     TEXT NOT NULL,
    cvss_score   NUMERIC(3,1),
    published_at TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ,
    description  TEXT,
    raw_data     JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    modified_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

Update `DATABASE_URL` in `schema.py` if needed:

```python
DATABASE_URL = "postgresql+psycopg2://postgres:vulns@localhost:5432/postgres"
```

### 4. Seed sample data

Run the seed script to insert sample CVEs into `security.cves`:

```bash
python seed_cves.py
```

Verify in psql:

```sql
SELECT * FROM security.cves LIMIT 5;
```

### 5. Run the server

Use Uvicorn to start the FastAPI app:

```bash
uvicorn main:app --reload
```

The API will be available at:

- GraphQL endpoint: `http://127.0.0.1:8000/graphql`
- Health check: `http://127.0.0.1:8000/health`

## GraphQL usage

Open the GraphQL IDE at `/graphql` or use `curl`.

### List CVEs

```graphql
query {
  cves(limit: 10) {
    id
    summary
    severity
    cvssScore
    publishedAt
    references
  }
}
```

### Get a single CVE

```graphql
query {
  cve(id: "CVE-2025-10001") {
    id
    summary
    severity
    cvssScore
    references
  }
}
```

containers

```container
query {
  containerAssets(publiclyExposed: true, runsAsRoot: true) {
    id
    name
    image
    publiclyExposed
    runsAsRoot
    cves {
      id
      summary
      severity
    }
  }
}
```


```container
query {
  containerAsset(id: 1) {
    name
    image
    publiclyExposed
    runsAsRoot
    cves {
      id
      cvssScore
    }
  }
}
```

`references` is derived from the `raw_data` JSON column (e.g., `raw_data.references`).

## Project structure

```text
.
├── main.py        # FastAPI + Strawberry GraphQL entrypoint
├── models.py      # SQLAlchemy models (CVE)
├── schema.py      # Strawberry GraphQL schema & resolvers
├── seed_cves.py   # Seed script to insert sample CVEs
├── requirements.txt
└── README.md
```

## Graph QL Mcp
```
brew install graphql-cli

pip3 install graphql-mcp
pip3 install mcp-graphql

pip3 show graphql-mcp
pip3 show mcp-graphql


graphql-mcp-server

export GRAPHQL_API_ENDPOINT="http://127.0.0.1:8000/graphql"

```

# If you add auth later, you can expose an API key or token here as well
# export GRAPHQL_API_KEY="..."
# Whitelist operations if you want to restrict tools:
# export WHITELISTED_QUERIES='["cves","cve","containerAssets","containerAsset"]'

## fastmcp

```
python3 -m venv .mcp-venv
source .mcp-venv/bin/activate

pip install fastmcp httpx
```
## final from claude

```

{
  "mcpServers": {
    "cve-graphql": {
      "command": "python",
      "args": ["mcp_server.py"],
      "env": {
        "GRAPHQL_API_ENDPOINT": "http://127.0.0.1:8000/graphql"
      }
    }
  }
}

```