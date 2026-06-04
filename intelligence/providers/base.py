from abc import ABC, abstractmethod

from models.threat_indicator import ThreatIndicator


class ThreatProvider(ABC):

    @abstractmethod
    async def lookup(
        self,
        indicator: str
    ) -> ThreatIndicator:
        pass
