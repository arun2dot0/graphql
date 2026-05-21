import strawberry
from strawberry.scalars import JSON
from typing import List, Optional
from datetime import datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from models import CVE, ContainerAsset

DATABASE_URL = "postgresql+psycopg2://postgres:vulns@localhost:5432/postgres"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

@strawberry.type
class CVEType:
    id: str
    summary: str
    severity: str
    cvss_score: Optional[float]
    published_at: Optional[datetime]
    updated_at: Optional[datetime]
    description: Optional[str]
    raw_data: Optional[JSON]

    @strawberry.field
    def references(self) -> JSON:
        return (self.raw_data or {}).get("references", [])

@strawberry.type
class ContainerAssetType:
    id: int
    name: str
    image: str
    registry: Optional[str]
    environment: Optional[str]
    namespace: Optional[str]
    service_name: Optional[str]
    publicly_exposed: bool
    runs_as_root: bool
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    cves: List[CVEType]

@strawberry.type
class Query:
    @strawberry.field
    def cves(
        self,
        severity: Optional[str] = None,
        limit: int = 20,
        published_after: Optional[datetime] = None,
        published_before: Optional[datetime] = None,
    ) -> List[CVEType]:
        with SessionLocal() as session:
            stmt = select(CVE)
            if severity:
                stmt = stmt.where(CVE.severity == severity)
            if published_after:
                stmt = stmt.where(CVE.published_at >= published_after)
            if published_before:
                stmt = stmt.where(CVE.published_at <= published_before)

            rows = session.execute(stmt.limit(limit)).scalars().all()

            return [
                CVEType(
                    id=row.id,
                    summary=row.summary,
                    severity=row.severity,
                    cvss_score=float(row.cvss_score) if row.cvss_score is not None else None,
                    published_at=row.published_at,
                    updated_at=row.updated_at,
                    description=row.description,
                    raw_data=row.raw_data,
                )
                for row in rows
            ]

    @strawberry.field
    def cve(self, id: str) -> Optional[CVEType]:
        with SessionLocal() as session:
            row = session.get(CVE, id)
            if not row:
                return None

            return CVEType(
                id=row.id,
                summary=row.summary,
                severity=row.severity,
                cvss_score=float(row.cvss_score) if row.cvss_score is not None else None,
                published_at=row.published_at,
                updated_at=row.updated_at,
                description=row.description,
                raw_data=row.raw_data,
            )
            
    @strawberry.field
    def container_assets(
        self,
        publicly_exposed: Optional[bool] = None,
        runs_as_root: Optional[bool] = None,
        limit: int = 20,
    ) -> List[ContainerAssetType]:
        with SessionLocal() as session:
            stmt = select(ContainerAsset)
            if publicly_exposed is not None:
                stmt = stmt.where(ContainerAsset.publicly_exposed == publicly_exposed)
            if runs_as_root is not None:
                stmt = stmt.where(ContainerAsset.runs_as_root == runs_as_root)

            result = session.execute(stmt.limit(limit))
            rows = result.unique().scalars().all()

            return [
                ContainerAssetType(
                    id=row.id,
                    name=row.name,
                    image=row.image,
                    registry=row.registry,
                    environment=row.environment,
                    namespace=row.namespace,
                    service_name=row.service_name,
                    publicly_exposed=row.publicly_exposed,
                    runs_as_root=row.runs_as_root,
                    created_at=row.created_at,
                    updated_at=row.updated_at,
                    cves=[
                        CVEType(
                            id=cve.id,
                            summary=cve.summary,
                            severity=cve.severity,
                            cvss_score=float(cve.cvss_score)
                            if cve.cvss_score is not None
                            else None,
                            published_at=cve.published_at,
                            updated_at=cve.updated_at,
                            description=cve.description,
                            raw_data=cve.raw_data,
                        )
                        for cve in row.cves
                    ],
                )
                for row in rows
            ]

    @strawberry.field
    def container_asset(self, id: int) -> Optional[ContainerAssetType]:
        with SessionLocal() as session:
            row = session.get(ContainerAsset, id)
            if not row:
                return None

            return ContainerAssetType(
                id=row.id,
                name=row.name,
                image=row.image,
                registry=row.registry,
                environment=row.environment,
                namespace=row.namespace,
                service_name=row.service_name,
                publicly_exposed=row.publicly_exposed,
                runs_as_root=row.runs_as_root,
                created_at=row.created_at,
                updated_at=row.updated_at,
                cves=[
                    CVEType(
                        id=cve.id,
                        summary=cve.summary,
                        severity=cve.severity,
                        cvss_score=float(cve.cvss_score)
                        if cve.cvss_score is not None
                        else None,
                        published_at=cve.published_at,
                        updated_at=cve.updated_at,
                        description=cve.description,
                        raw_data=cve.raw_data,
                    )
                    for cve in row.cves
                ],
            )        

schema = strawberry.Schema(query=Query)