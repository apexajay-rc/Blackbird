from models.threat_indicator import ThreatIndicator


class ThreatScoringEngine:

    def calculate(
        self,
        indicators: list[ThreatIndicator]
    ) -> dict:

        score = 0

        findings = []

        score_breakdown = []

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

                score_breakdown.append(
                    f"Malicious detections: +{points}"
                )

            if indicator.report_count:

                points = min(
                    indicator.report_count // 5,
                    20
                )

                score += points

                score_breakdown.append(
                    f"Abuse reports: +{points}"
                )

            if indicator.confidence:

                points = min(
                    indicator.confidence // 2,
                    20
                )

                score += points

                score_breakdown.append(
                    f"Provider confidence: +{points}"
                )

            if indicator.findings:

                score += 20

                score_breakdown.append(
                    "Threat intelligence findings: +20"
                )

            #
            # Positive Signals
            #

            if indicator.reputation > 100:

                score -= 10

                score_breakdown.append(
                    "Positive reputation: -10"
                )

            if indicator.harmless_count > 20:

                score -= 10

                score_breakdown.append(
                    "Harmless verdicts: -10"
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
            risk_level = "critical"

        elif score >= 60:
            risk_level = "high"

        elif score >= 40:
            risk_level = "medium"

        elif score >= 20:
            risk_level = "low"

        else:
            risk_level = "minimal"

        return {
            "score": score,
            "risk_level": risk_level,
            "findings": list(
                set(findings)
            ),
            "score_breakdown": score_breakdown
        }
