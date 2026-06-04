from pydantic import BaseModel, Field

from models.threat_indicator import (
    ThreatIndicator
)


class ThreatReport(BaseModel):

    value: str

    indicator_type: str

    overall_score: int = 0

    risk_level: str = "unknown"

    findings: list[str] = Field(
        default_factory=list
    )

    score_breakdown: list[str] = Field(
        default_factory=list
    )

    provider_results: list[ThreatIndicator] = Field(
        default_factory=list
    )
