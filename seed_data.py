import json
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import execute_values, Json

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "postgres",
    "user": "postgres",
    "password": "vulns",
}

CVES = [
    {
        "cve_id": "CVE-2025-10001",
        "summary": "Example SQL injection in admin search endpoint.",
        "severity": "HIGH",
        "cvss_score": 8.8,
        "published_at": "2025-01-12T10:15:00Z",
        "updated_at": "2025-01-15T09:00:00Z",
        "description": "Improper input validation allows SQL injection in the admin search endpoint.",
        "references": [
            {"url": "https://example.com/advisory-10001", "source": "vendor", "tags": ["advisory"]},
            {"url": "https://example.com/patch-10001", "source": "vendor", "tags": ["patch"]},
        ],
        "cwes": ["CWE-89"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "LOW"},
        },
    },
    {
        "cve_id": "CVE-2025-10002",
        "summary": "Example cross-site scripting in comment renderer.",
        "severity": "MEDIUM",
        "cvss_score": 6.1,
        "published_at": "2025-02-20T14:30:00Z",
        "updated_at": "2025-02-22T08:20:00Z",
        "description": "Unsanitized HTML is reflected in the comment rendering pipeline.",
        "references": [
            {"url": "https://example.com/advisory-10002", "source": "vendor", "tags": ["advisory"]},
        ],
        "cwes": ["CWE-79"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "LOW", "integrity": "LOW", "availability": "NONE"},
        },
    },
    {
        "cve_id": "CVE-2025-10003",
        "summary": "Example insecure deserialization in job worker.",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "published_at": "2025-03-05T16:45:00Z",
        "updated_at": "2025-03-06T11:10:00Z",
        "description": "Untrusted serialized payloads can trigger remote code execution.",
        "references": [
            {"url": "https://example.com/advisory-10003", "source": "research", "tags": ["analysis"]},
        ],
        "cwes": ["CWE-502"],
        "raw_data": {
            "source": "sample",
            "impact": {"confidentiality": "HIGH", "integrity": "HIGH", "availability": "HIGH"},
        },
    },
]

def iso_to_dt(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

def main():
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn:
            with conn.cursor() as cur:
                for cve in CVES:
                    cur.execute(
                        """
                        INSERT INTO security.cves (
                            cve_id, summary, severity, cvss_score,
                            published_at, updated_at, description, raw_data
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (cve_id) DO UPDATE SET
                            summary = EXCLUDED.summary,
                            severity = EXCLUDED.severity,
                            cvss_score = EXCLUDED.cvss_score,
                            published_at = EXCLUDED.published_at,
                            updated_at = EXCLUDED.updated_at,
                            description = EXCLUDED.description,
                            raw_data = EXCLUDED.raw_data,
                            modified_at = NOW()
                        """,
                        (
                            cve["cve_id"],
                            cve["summary"],
                            cve["severity"],
                            cve["cvss_score"],
                            iso_to_dt(cve["published_at"]),
                            iso_to_dt(cve["updated_at"]),
                            cve["description"],
                            Json(cve["raw_data"]),
                        ),
                    )

                    cur.execute(
                        "DELETE FROM security.cve_references WHERE cve_id = %s",
                        (cve["cve_id"],),
                    )
                    ref_rows = [
                        (
                            cve["cve_id"],
                            ref["url"],
                            ref.get("source"),
                            Json(ref.get("tags", [])),
                        )
                        for ref in cve["references"]
                    ]
                    execute_values(
                        cur,
                        """
                        INSERT INTO security.cve_references (cve_id, url, source, tags)
                        VALUES %s
                        """,
                        ref_rows,
                    )

                    cur.execute(
                        "DELETE FROM security.cve_cwes WHERE cve_id = %s",
                        (cve["cve_id"],),
                    )
                    cwe_rows = [(cve["cve_id"], cwe) for cwe in cve["cwes"]]
                    execute_values(
                        cur,
                        """
                        INSERT INTO security.cve_cwes (cve_id, cwe_id)
                        VALUES %s
                        """,
                        cwe_rows,
                    )
        print("Seed data inserted successfully.")
    finally:
        conn.close()

if __name__ == "__main__":
    main()