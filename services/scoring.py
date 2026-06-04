from models.threat_indicator import (
    ThreatIndicator
)


class ThreatScoringEngine:

    def calculate(
        self,
        indicators: list[ThreatIndicator]
    ):

        score = 0

        findings = []

        breakdown = []

        for indicator in indicators:

            #
            # Negative Signals
            #

            if indicator.malicious_count:

                points = min(
                    indicator.malicious_count * 5,
                    40
                )

                score += points

                breakdown.append(
                    f"Malicious detections: +{points}"
                )

            if indicator.report_count:

                points = min(
                    indicator.report_count // 5,
                    20
                )

                score += points

                breakdown.append(
                    f"Abuse reports: +{points}"
                )

            if indicator.confidence:

                points = min(
                    indicator.confidence // 2,
                    20
                )

                score += points

                breakdown.append(
                    f"Provider confidence: +{points}"
                )

            if indicator.findings:

                score += 20

                breakdown.append(
                    "Threat intelligence findings: +20"
                )

            #
            # Positive Signals
            #

            if indicator.reputation > 100:

                score -= 10

                breakdown.append(
                    "Strong positive reputation: -10"
                )

            if indicator.harmless_count > 20:

                score -= 10

                breakdown.append(
                    "Multiple harmless verdicts: -10"
                )

            findings.extend(
                indicator.findings
            )

            findings.extend(
                indicator.categories
            )

        score = max(
            0,
            min(score, 100)
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

        return {
            "score": score,
            "risk_level": risk,
            "findings": list(
                set(findings)
            ),
            "breakdown": breakdown
        }
