from sqlalchemy import (
    Column, Text, Numeric, DateTime, Boolean, Integer, ForeignKey, Table
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class CVE(Base):
    __tablename__ = "cves"
    __table_args__ = {"schema": "security"}

    id = Column("cve_id", Text, primary_key=True)
    summary = Column(Text, nullable=False)
    severity = Column(Text, nullable=False)
    cvss_score = Column(Numeric(3, 1))
    published_at = Column(DateTime(timezone=True))
    updated_at = Column(DateTime(timezone=True))
    description = Column(Text)
    raw_data = Column(JSONB)
    created_at = Column(DateTime(timezone=True))
    modified_at = Column(DateTime(timezone=True))

# association / join table
container_asset_cves = Table(
    "container_asset_cves",
    Base.metadata,
    Column(
        "container_id",
        Integer,
        ForeignKey("security.container_assets.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "cve_id",
        Text,
        ForeignKey("security.cves.cve_id", ondelete="CASCADE"),
        primary_key=True,
    ),
    schema="security",
)

class ContainerAsset(Base):
    __tablename__ = "container_assets"
    __table_args__ = {"schema": "security"}

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(Text, nullable=False)
    image = Column(Text, nullable=False)
    registry = Column(Text)
    environment = Column(Text)
    namespace = Column(Text)
    service_name = Column(Text)
    publicly_exposed = Column(Boolean, nullable=False, default=False)
    runs_as_root = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True))
    updated_at = Column(DateTime(timezone=True))

    cves = relationship(
        "CVE",
        secondary=container_asset_cves,
        backref="container_assets",
        lazy="joined",
    )