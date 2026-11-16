"""Command-line interface for extracting IOCs from a text file."""

import argparse
import os
import sys

import requests
from dotenv import load_dotenv

from extractor import IOC_TYPES, extract_iocs

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_MAX_AGE_DAYS = 90


def check_ip_abuseipdb(ip_address, api_key):
    """Look up an IP address in AbuseIPDB and return the report data.

    Query the CHECK endpoint and return the "data" dict from the JSON
    response (e.g. abuseConfidenceScore, countryCode, totalReports).
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
    return response.json()["data"]


parser = argparse.ArgumentParser(
    description="Extract IOCs (IPs, URLs, domains, hashes) from a text file.")
parser.add_argument("input_file", help="path to the input text file")
parser.add_argument(
    "-t",
    "--types",
    nargs="+",
    choices=IOC_TYPES,
    default=IOC_TYPES,
    metavar="TYPE",
    help=f"IOC types to show: {', '.join(IOC_TYPES)} (default: all)",
)
args = parser.parse_args()

try:
    with open(args.input_file, encoding="utf-8") as f:
        raw_text = f.read()
except OSError as error:
    parser.error(f"cannot read {args.input_file}: {error.strerror}")
except UnicodeDecodeError:
    parser.error(f"{args.input_file} is not a UTF-8 text file")

iocs = extract_iocs(raw_text)

if "ips" in args.types:
    for invalid_ip in iocs["invalid_ips"]:
        print(f"Skipping invalid IP address: {invalid_ip}")

    print("\nIP addresses:")
    # is_global is False for private, loopback and documentation IPs.
    for ip in iocs["valid_ips"]:
        if ip.is_global:
            print(f"{ip} --- public")
        else:
            print(f"{ip} --- non-public")

if "urls" in args.types:
    print("\nURLs:")
    for url in iocs["urls"]:
        print(url)

if "domains" in args.types:
    print("\nDomains:")
    for domain in iocs["domains"]:
        print(domain)

if "hashes" in args.types:
    print("\nHashes:")
    for hash_type, hashes in iocs["hashes"].items():
        print(hash_type)
        for hash_value in hashes:
            print(hash_value)

load_dotenv()
api_key = os.getenv("ABUSEIPDB_API_KEY")
if not api_key:
    sys.exit(
        "error: ABUSEIPDB_API_KEY is not set. "
        "Add your AbuseIPDB API key to .env (see .env.example)."
    )

abuseipdb_result = check_ip_abuseipdb("8.8.8.8", api_key)

checked_ip = abuseipdb_result["ipAddress"]
abuse_score = abuseipdb_result["abuseConfidenceScore"]

print("\nAbuseIPDB results:")
print(f"{checked_ip} --- abuse confidence score: {abuse_score}/100")
