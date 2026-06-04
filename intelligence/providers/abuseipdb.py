import httpx

from fastapi import HTTPException

from app.config import ABUSEIPDB_API_KEY

from intelligence.providers.base import ThreatProvider

from models.threat_indicator import ThreatIndicator


class AbuseIPDBProvider(ThreatProvider):

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    async def lookup(
        self,
        indicator: str
    ) -> ThreatIndicator:

        if not ABUSEIPDB_API_KEY:
            raise HTTPException(
                status_code=500,
                detail="AbuseIPDB API key not configured"
            )

        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }

        params = {
            "ipAddress": indicator,
            "maxAgeInDays": 90,
            "verbose": True
        }

        async with httpx.AsyncClient() as client:

            response = await client.get(
                self.BASE_URL,
                headers=headers,
                params=params
            )

        if response.status_code == 401:
            raise HTTPException(
                status_code=401,
                detail="Invalid AbuseIPDB API key"
            )

        if response.status_code == 429:
            raise HTTPException(
                status_code=429,
                detail="AbuseIPDB rate limit exceeded"
            )

        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail="AbuseIPDB lookup failed"
            )

        data = response.json()

        abuse_data = data.get(
            "data",
            {}
        )

        confidence_score = abuse_data.get(
            "abuseConfidenceScore",
            0
        )

        total_reports = abuse_data.get(
            "totalReports",
            0
        )

        categories = []

        if confidence_score >= 75:
            categories.append(
                "High Abuse Confidence"
            )

        elif confidence_score >= 40:
            categories.append(
                "Moderate Abuse Confidence"
            )

        return ThreatIndicator(
            value=indicator,
            indicator_type="ip",

            confidence=confidence_score,

            report_count=total_reports,

            categories=categories,

            sources=["AbuseIPDB"],

            raw_data=data
        )
