import httpx

from fastapi import HTTPException

from app.config import VT_API_KEY

from intelligence.providers.base import ThreatProvider

from models.threat_indicator import ThreatIndicator


class VirusTotalProvider(ThreatProvider):

    BASE_URL = "https://www.virustotal.com/api/v3"

    async def lookup(
        self,
        indicator: str
    ) -> ThreatIndicator:

        if not VT_API_KEY:
            raise HTTPException(
                status_code=500,
                detail="VirusTotal API key not configured"
            )

        headers = {
            "x-apikey": VT_API_KEY
        }

        async with httpx.AsyncClient() as client:

            response = await client.get(
                f"{self.BASE_URL}/ip_addresses/{indicator}",
                headers=headers
            )

        if response.status_code == 401:
            raise HTTPException(
                status_code=401,
                detail="Invalid VirusTotal API key"
            )

        if response.status_code == 429:
            raise HTTPException(
                status_code=429,
                detail="VirusTotal rate limit exceeded"
            )

        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail="VirusTotal lookup failed"
            )

        data = response.json()

        attributes = (
            data.get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        malicious = stats.get(
            "malicious",
            0
        )

        suspicious = stats.get(
            "suspicious",
            0
        )

        harmless = stats.get(
            "harmless",
            0
        )

        reputation = attributes.get(
            "reputation",
            0
        )

        findings = []

        contexts = attributes.get(
            "crowdsourced_context",
            []
        )

        for context in contexts:

            title = context.get(
                "title"
            )

            details = context.get(
                "details"
            )

            if title:
                findings.append(title)

            if details:
                findings.append(details)

        confidence = min(
            (malicious * 10)
            + (suspicious * 5),
            100
        )

        return ThreatIndicator(
            value=indicator,
            indicator_type="ip",

            confidence=confidence,

            malicious_count=malicious,
            suspicious_count=suspicious,
            harmless_count=harmless,

            reputation=reputation,

            findings=findings,

            sources=["VirusTotal"],

            raw_data=data
        )
