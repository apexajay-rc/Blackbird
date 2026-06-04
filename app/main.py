from fastapi import FastAPI
from intelligence.providers.abuseipdb import AbuseIPDBProvider
from app.db.database import engine
from app.db.database import Base
from services.aggregator import ThreatAggregator
import app.db.models

from intelligence.providers.virustotal import VirusTotalProvider

app = FastAPI(
    title="Threat Intelligence Dashboard",
    version="0.1.0"
)


@app.on_event("startup")
async def startup():

    async with engine.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all
        )


@app.get("/")
async def root():

    return {
        "status": "running",
        "service": "threat-intelligence-dashboard"
    }


@app.get("/test-vt/{ip}")
async def test_vt(ip: str):

    provider = VirusTotalProvider()

    result = await provider.lookup(ip)

    return result.model_dump()

@app.get("/test-abuse/{ip}")
async def test_abuse(ip: str):

    provider = AbuseIPDBProvider()

    result = await provider.lookup(ip)

    return result.model_dump()

@app.get("/lookup/{ip}")
async def lookup(ip: str):

    aggregator = ThreatAggregator()

    report = await aggregator.lookup(ip)

    return report.model_dump()
