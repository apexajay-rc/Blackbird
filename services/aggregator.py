import asyncio

from intelligence.registry import (
    get_providers
)

from models.threat_report import (
    ThreatReport
)

from services.scoring import (
    ThreatScoringEngine
)


class ThreatAggregator:

    def __init__(self):

        self.providers = get_providers()

        self.scoring_engine = (
            ThreatScoringEngine()
        )

    async def lookup(
        self,
        indicator: str
    ) -> ThreatReport:

        results = await asyncio.gather(
            *[
                provider.lookup(indicator)
                for provider in self.providers
            ],
            return_exceptions=True
        )

        provider_results = []

        for result in results:

            if isinstance(
                result,
                Exception
            ):
                continue

            provider_results.append(
                result
            )

        scoring = (
            self.scoring_engine.calculate(
                provider_results
            )
        )

        return ThreatReport(
            value=indicator,

            indicator_type="ip",

            overall_score=scoring[
                "score"
            ],

            risk_level=scoring[
                "risk_level"
            ],

            findings=scoring[
                "findings"
            ],

            score_breakdown=scoring[
                "breakdown"
            ],

            provider_results=provider_results
        )
