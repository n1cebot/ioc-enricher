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
# Used by main.py to wait between requests.
VIRUSTOTAL_REQUEST_INTERVAL_SECONDS = 15


def check_ip_abuseipdb(ip_address, api_key):
    """Check an IP in AbuseIPDB and return the "data" dict.

    The field we use is abuseConfidenceScore (0-100). Errors from
    requests (HTTPError, ConnectionError, Timeout) are not caught
    here; the caller handles them.
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
    """Check an IOC in VirusTotal and return the "attributes" dict.

    ioc_type is a key of VIRUSTOTAL_COLLECTIONS, e.g. "ips". URLs are
    passed as plain text and encoded here. The field we use is
    last_analysis_stats.

    Raise KeyError for an unknown ioc_type. Errors from requests
    (HTTPError, ConnectionError, Timeout) are not caught here; the
    caller handles them.
    """
    # VirusTotal identifies URLs by unpadded URL-safe base64.
    if ioc_type == "urls":
        encoded_url = base64.urlsafe_b64encode(ioc_value.encode())
        ioc_id = encoded_url.decode().rstrip("=")
    else:
        ioc_id = ioc_value

    collection = VIRUSTOTAL_COLLECTIONS[ioc_type]
    api_url = f"{VIRUSTOTAL_BASE_URL}/{collection}/{ioc_id}"

    headers = {
        "Accept": "application/json",
        "x-apikey": api_key,
    }

    response = requests.get(
        api_url,
        headers=headers,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()["data"]["attributes"]
