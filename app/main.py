from fastapi import FastAPI

from models.threat_indicator import ThreatIndicator

app = FastAPI()

@app.get("/")
async def root():

    example = ThreatIndicator(
        value="8.8.8.8",
        indicator_type="ip"
    )

    return example.model_dump()
