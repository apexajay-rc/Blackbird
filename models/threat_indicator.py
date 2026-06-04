from pydantic import BaseModel, Field


class ThreatIndicator(BaseModel):

    value: str
    indicator_type: str

    risk_score: int = 0

    confidence: int = 0

    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0

    reputation: int = 0

    report_count: int = 0

    categories: list[str] = Field(
        default_factory=list
    )

    findings: list[str] = Field(
        default_factory=list
    )

    sources: list[str] = Field(
        default_factory=list
    )

    raw_data: dict = Field(
        default_factory=dict
    )
