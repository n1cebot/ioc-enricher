"""Check IP address reputation in AbuseIPDB and VirusTotal."""

import requests

# requests has no default timeout; a dead server could hang the program.
REQUEST_TIMEOUT_SECONDS = 10

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

# AbuseIPDB defaults to 30 days; 90 gives a longer report history.
ABUSEIPDB_MAX_AGE_DAYS = 90

VIRUSTOTAL_IP_ADDRESSES_URL = "https://www.virustotal.com/api/v3/ip_addresses"


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
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()["data"]


def check_ip_virustotal(ip_address, api_key):
    """Look up an IP address in VirusTotal and return its attributes.

    Query the IP address endpoint and return the "attributes" dict from
    the JSON response (e.g. last_analysis_stats, reputation, country).

    Raise requests.HTTPError for an error status code,
    requests.ConnectionError if VirusTotal cannot be reached, and
    requests.Timeout if it does not respond in time.
    """
    headers = {
        "Accept": "application/json",
        "x-apikey": api_key,
    }

    response = requests.get(
        f"{VIRUSTOTAL_IP_ADDRESSES_URL}/{ip_address}",
        headers=headers,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()["data"]["attributes"]
