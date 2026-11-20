"""Look up IOC reputation in AbuseIPDB and VirusTotal."""

import base64

import requests

# requests has no default timeout; a dead server could hang the program.
REQUEST_TIMEOUT_SECONDS = 10

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

# AbuseIPDB defaults to 30 days; 90 gives a longer report history.
ABUSEIPDB_MAX_AGE_DAYS = 90

VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"

# Keys are IOC_TYPES names; values are VirusTotal collection names.
VIRUSTOTAL_COLLECTIONS = {
    "ips": "ip_addresses",
    "urls": "urls",
    "domains": "domains",
    "hashes": "files",
}

# The free API allows 4 requests per minute; 60 s / 4 = 15 s.
VIRUSTOTAL_REQUEST_INTERVAL_SECONDS = 15


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


def check_virustotal(ioc_type, ioc_value, api_key):
    """Look up an IOC in VirusTotal and return its attributes.

    Map ioc_type (a key of VIRUSTOTAL_COLLECTIONS, e.g. "ips") to a
    VirusTotal collection, query it for ioc_value (URLs are encoded as
    VirusTotal identifiers first) and return the "attributes" dict
    from the JSON response (e.g. last_analysis_stats, reputation).

    Raise KeyError for an unsupported ioc_type, requests.HTTPError
    for an error status code, requests.ConnectionError if VirusTotal
    cannot be reached, and requests.Timeout if it does not respond in
    time.
    """
    # VirusTotal identifies URLs by unpadded URL-safe base64.
    if ioc_type == "urls":
        encoded_url = base64.urlsafe_b64encode(ioc_value.encode())
        ioc_id = encoded_url.decode().rstrip("=")
    else:
        ioc_id = ioc_value

    collection = VIRUSTOTAL_COLLECTIONS[ioc_type]
    url = f"{VIRUSTOTAL_BASE_URL}/{collection}/{ioc_id}"

    headers = {
        "Accept": "application/json",
        "x-apikey": api_key,
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()["data"]["attributes"]
