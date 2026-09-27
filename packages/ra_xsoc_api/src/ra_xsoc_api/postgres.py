from __future__ import annotations

import json
import os
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, Float, String, Text, create_engine, select
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

class Base(DeclarativeBase):
    pass

class AnalysisCase(Base):
    __tablename__ = "analysis_cases"
    analysis_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    incident_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    review_status: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[str] = mapped_column(String(64), index=True)
    updated_at: Mapped[str] = mapped_column(String(64))

class FeedbackRecord(Base):
    __tablename__ = "feedback"
    feedback_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    analysis_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), index=True)
    analyst_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), index=True)
    status: Mapped[str] = mapped_column(String(32))
    comments: Mapped[str] = mapped_column(Text)
    corrected_attack_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64))

class PostgresCaseStore:
    def __init__(self, url: str | None = None) -> None:
        self.url = url or os.getenv("RA_XSOC_DATABASE_URL")
        if not self.url:
            raise RuntimeError("RA_XSOC_DATABASE_URL is required for PostgreSQL persistence.")
        self.engine = create_engine(self.url, pool_pre_ping=True)
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)

    def save_analysis(self, payload: dict[str, Any]) -> None:
        with self.sessions.begin() as session:
            existing = session.get(AnalysisCase, UUID(str(payload["analysis_id"])))
            row = existing or AnalysisCase(analysis_id=UUID(str(payload["analysis_id"])))
            row.incident_id = UUID(str(payload["incident_id"]))
            row.payload = payload
            row.review_status = payload["review_status"]
            row.created_at = payload["created_at"]
            row.updated_at = payload["created_at"]
            session.add(row)

    def get_analysis(self, analysis_id: UUID) -> dict[str, Any] | None:
        with self.sessions() as session:
            row = session.get(AnalysisCase, analysis_id)
            return row.payload if row else None

    def list_cases(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.sessions() as session:
            rows = session.scalars(
                select(AnalysisCase).order_by(AnalysisCase.created_at.desc()).limit(min(max(limit,1),200))
            ).all()
            return [row.payload for row in rows]

    def update_review_status(self, analysis_id: UUID, status: str) -> dict[str, Any] | None:
        with self.sessions.begin() as session:
            row = session.get(AnalysisCase, analysis_id)
            if not row:
                return None
            row.payload["review_status"] = status
            row.review_status = status
            return row.payload

    def save_feedback(self, feedback: dict[str, Any]) -> None:
        with self.sessions.begin() as session:
            session.add(FeedbackRecord(
                feedback_id=UUID(str(feedback["feedback_id"])),
                analysis_id=UUID(str(feedback["analysis_id"])),
                analyst_id=UUID(str(feedback["analyst_id"])),
                status=feedback["status"],
                comments=feedback["comments"],
                corrected_attack_id=feedback.get("corrected_attack_id"),
                created_at=feedback["created_at"],
            ))
