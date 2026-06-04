from sqlalchemy import (
    String,
    Integer,
    DateTime
)

from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from datetime import datetime

from app.db.database import Base


class IOCSearch(Base):
    __tablename__ = "ioc_searches"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )

    indicator: Mapped[str] = mapped_column(
        String(255)
    )

    indicator_type: Mapped[str] = mapped_column(
        String(50)
    )

    threat_score: Mapped[int] = mapped_column(
        Integer,
        default=0
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )
