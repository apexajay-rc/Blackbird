from intelligence.providers.virustotal import (
    VirusTotalProvider
)

from intelligence.providers.abuseipdb import (
    AbuseIPDBProvider
)


def get_providers():

    return [
        VirusTotalProvider(),
        AbuseIPDBProvider()
    ]
