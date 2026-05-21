# seed_container_assets.py
import psycopg2
from psycopg2.extras import execute_values
from datetime import datetime, timezone

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "postgres",
    "user": "postgres",
    "password": "vulns",
}

CONTAINERS = [
    {
        "name": "payments-api",
        "image": "registry.example.com/payments-api:1.0.0",
        "registry": "registry.example.com",
        "environment": "prod",
        "namespace": "payments",
        "service_name": "payments-api",
        "publicly_exposed": True,
        "runs_as_root": True,
        "cves": ["CVE-2025-10001", "CVE-2025-10003"],
    },
    {
        "name": "analytics-worker",
        "image": "registry.example.com/analytics-worker:2.3.1",
        "registry": "registry.example.com",
        "environment": "prod",
        "namespace": "analytics",
        "service_name": "analytics-worker",
        "publicly_exposed": False,
        "runs_as_root": False,
        "cves": ["CVE-2025-10002"],
    },
    {
        "name": "frontend-web",
        "image": "registry.example.com/frontend-web:3.4.5",
        "registry": "registry.example.com",
        "environment": "staging",
        "namespace": "frontend",
        "service_name": "frontend-web",
        "publicly_exposed": True,
        "runs_as_root": False,
        "cves": [],
    },
    {
        "name": "internal-reporting-api",
        "image": "registry.example.com/internal-reporting-api:0.9.0",
        "registry": "registry.example.com",
        "environment": "prod",
        "namespace": "reporting",
        "service_name": "internal-reporting-api",
        "publicly_exposed": False,
        "runs_as_root": True,
        "cves": ["CVE-2025-10001"],
    },
]

def main():
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn:
            with conn.cursor() as cur:
                # Insert containers
                container_rows = [
                    (
                        c["name"],
                        c["image"],
                        c["registry"],
                        c["environment"],
                        c["namespace"],
                        c["service_name"],
                        c["publicly_exposed"],
                        c["runs_as_root"],
                    )
                    for c in CONTAINERS
                ]

                execute_values(
                    cur,
                    """
                    INSERT INTO security.container_assets (
                        name, image, registry, environment,
                        namespace, service_name,
                        publicly_exposed, runs_as_root
                    )
                    VALUES %s
                    RETURNING id, name
                    """,
                    container_rows,
                )

                # Fetch ids so we can populate the join table
                cur.execute(
                    "SELECT id, name FROM security.container_assets ORDER BY id"
                )
                id_by_name = {name: cid for cid, name in cur.fetchall()}

                # Build join table entries
                join_rows = []
                for c in CONTAINERS:
                    cid = id_by_name.get(c["name"])
                    if not cid:
                        continue
                    for cve_id in c["cves"]:
                        join_rows.append((cid, cve_id))

                if join_rows:
                    execute_values(
                        cur,
                        """
                        INSERT INTO security.container_asset_cves (container_id, cve_id)
                        VALUES %s
                        ON CONFLICT DO NOTHING
                        """,
                        join_rows,
                    )

        print("Seeded container assets and associations successfully.")
    finally:
        conn.close()

if __name__ == "__main__":
    main()