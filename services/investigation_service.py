from sqlalchemy import select

from app.db.database import AsyncSessionLocal
from app.db.models import Investigation

from models.threat_report import ThreatReport


class InvestigationService:

    async def create(
        self,
        report: ThreatReport,
    ) -> Investigation:

        async with AsyncSessionLocal() as session:

            investigation = Investigation(
                indicator=report.value,
                indicator_type=report.indicator_type,
                overall_score=report.overall_score,
                risk_level=report.risk_level,
                findings=report.findings,
                score_breakdown=report.score_breakdown,
                provider_results=[
                    provider.model_dump()
                    for provider in report.provider_results
                ],
            )

            session.add(investigation)

            await session.commit()

            await session.refresh(investigation)

            return investigation

    async def list_recent(
        self,
        limit: int = 20,
    ):

        async with AsyncSessionLocal() as session:

            result = await session.execute(
                select(Investigation)
                .order_by(Investigation.created_at.desc())
                .limit(limit)
            )

            return result.scalars().all()
