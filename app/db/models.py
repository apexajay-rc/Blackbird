from datetime import datetime

from sqlalchemy import (
    DateTime,
    Integer,
    JSON,
    String,
)

from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from app.db.database import Base


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    indicator: Mapped[str] = mapped_column(
        String(255),
        index=True,
    )

    indicator_type: Mapped[str] = mapped_column(
        String(50),
    )

    overall_score: Mapped[int] = mapped_column(
        Integer,
    )

    risk_level: Mapped[str] = mapped_column(
        String(30),
    )

    findings: Mapped[list] = mapped_column(
        JSON,
        default=list,
    )

    score_breakdown: Mapped[list] = mapped_column(
        JSON,
        default=list,
    )

    provider_results: Mapped[list] = mapped_column(
        JSON,
        default=list,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )
