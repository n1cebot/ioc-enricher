"""Command-line interface for extracting IOCs from a text file."""

import argparse
import os
import sys
import time

import requests
from dotenv import load_dotenv

from enrich import check_ip_abuseipdb
from extractor import IOC_TYPES, extract_iocs

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

public_ips = [ip for ip in iocs["valid_ips"] if ip.is_global]

if "ips" in args.types and public_ips:
    load_dotenv()
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        sys.exit(
            "error: ABUSEIPDB_API_KEY is not set. "
            "Add your AbuseIPDB API key to .env (see .env.example)."
        )

    print("\nAbuseIPDB results:")
    start_time = time.perf_counter()
    for ip in public_ips:
        try:
            abuseipdb_result = check_ip_abuseipdb(str(ip), api_key)
        except requests.HTTPError as error:
            status_code = error.response.status_code
            if status_code == 401:
                sys.exit(
                    "error: AbuseIPDB rejected the API key (HTTP 401). "
                    "Check ABUSEIPDB_API_KEY in .env."
                )
            elif status_code == 429:
                sys.exit(
                    "error: AbuseIPDB daily request limit reached (HTTP 429). "
                    "Try again tomorrow."
                )
            elif 500 <= status_code <= 599:
                print(
                    f"{ip} --- not checked: AbuseIPDB server error "
                    f"(HTTP {status_code})"
                )
                continue
            else:
                print(
                    f"{ip} --- not checked: request failed "
                    f"(HTTP {status_code})"
                )
                continue
        except requests.Timeout:
            print(f"{ip} --- not checked: no response in time")
            continue
        except requests.ConnectionError:
            sys.exit(
                "error: cannot connect to AbuseIPDB. "
                "Check your internet connection."
            )

        checked_ip = abuseipdb_result["ipAddress"]
        abuse_score = abuseipdb_result["abuseConfidenceScore"]
        print(f"{checked_ip} --- abuse confidence score: {abuse_score}/100")

    elapsed_seconds = time.perf_counter() - start_time
    print(f"\nAbuseIPDB lookups: {len(public_ips)} in {elapsed_seconds:.2f} s")
