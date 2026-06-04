import asyncio

from intelligence.registry import (
    get_providers
)

from models.threat_report import (
    ThreatReport
)


class ThreatAggregator:

    def __init__(self):

        self.providers = get_providers()

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

        findings = []

        score_breakdown = []

        score = 0

        for result in results:

            if isinstance(
                result,
                Exception
            ):
                continue

            provider_results.append(
                result
            )

            if result.malicious_count:

                points = min(
                    result.malicious_count * 5,
                    40
                )

                score += points

                score_breakdown.append(
                    f"Malicious detections: +{points}"
                )

            if result.report_count:

                points = min(
                    result.report_count // 5,
                    20
                )

                score += points

                score_breakdown.append(
                    f"Abuse reports: +{points}"
                )

            if result.confidence:

                points = min(
                    result.confidence // 2,
                    20
                )

                score += points

                score_breakdown.append(
                    f"Provider confidence: +{points}"
                )

            if result.findings:

                score += 20

                score_breakdown.append(
                    "Threat intelligence findings: +20"
                )

            findings.extend(
                result.findings
            )

            findings.extend(
                result.categories
            )

        score = min(
            score,
            100
        )

        if score >= 80:
            risk = "critical"

        elif score >= 60:
            risk = "high"

        elif score >= 40:
            risk = "medium"

        elif score >= 20:
            risk = "low"

        else:
            risk = "minimal"

        return ThreatReport(
            value=indicator,

            indicator_type="ip",

            overall_score=score,

            risk_level=risk,

            findings=list(
                set(findings)
            ),

            score_breakdown=score_breakdown,

            provider_results=provider_results
        )
