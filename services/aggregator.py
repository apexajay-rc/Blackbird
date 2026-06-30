import asyncio

from intelligence.registry import get_providers

from models.threat_indicator import ThreatIndicator
from models.threat_report import ThreatReport

from services.scoring import ThreatScoringEngine


class ThreatAggregator:

    def __init__(self):

        self.providers = get_providers()

        self.scoring_engine = ThreatScoringEngine()

    async def lookup(
        self,
        indicator: str
    ) -> ThreatReport:

        provider_results = await self.collect_provider_results(
            indicator
        )

        scoring = self.scoring_engine.calculate(
            provider_results
        )

        return self.build_report(
            indicator,
            provider_results,
            scoring
        )

    async def collect_provider_results(
        self,
        indicator: str
    ) -> list[ThreatIndicator]:

        results = await asyncio.gather(
            *[
                provider.lookup(indicator)
                for provider in self.providers
            ],
            return_exceptions=True
        )

        return [
            result
            for result in results
            if not isinstance(result, Exception)
        ]

    def build_report(
        self,
        indicator: str,
        provider_results: list[ThreatIndicator],
        scoring: dict
    ) -> ThreatReport:

        return ThreatReport(
            value=indicator,
            indicator_type="ip",
            overall_score=scoring["score"],
            risk_level=scoring["risk_level"],
            findings=scoring["findings"],
            score_breakdown=scoring["score_breakdown"],
            provider_results=provider_results,
        )
