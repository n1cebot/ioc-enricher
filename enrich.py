"""Check IP address reputation in AbuseIPDB."""

import requests

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_MAX_AGE_DAYS = 90


def check_ip_abuseipdb(ip_address, api_key):
    """Look up an IP address in AbuseIPDB and return the report data.

    Query the CHECK endpoint and return the "data" dict from the JSON
    response (e.g. abuseConfidenceScore, countryCode, totalReports).

    Raise requests.HTTPError for an error status code,
    requests.ConnectionError if AbuseIPDB cannot be reached, and
    requests.Timeout if it does not respond in time.
    """
    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": ABUSEIPDB_MAX_AGE_DAYS,
    }

    response = requests.get(
        ABUSEIPDB_CHECK_URL,
        headers=headers,
        params=params,
        timeout=10,
    )
    response.raise_for_status()
    return response.json()["data"]
