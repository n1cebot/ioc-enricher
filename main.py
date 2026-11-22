"""Extract IOCs from a text file and look up their reputation.

Public IPs are checked in AbuseIPDB and VirusTotal. URLs, domains, and
hashes are checked in VirusTotal only.
"""

import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests
from dotenv import load_dotenv

from cache import current_timestamp, load_cache, save_cache
from enrich import (
    VIRUSTOTAL_REQUEST_INTERVAL_SECONDS,
    check_ip_abuseipdb,
    check_virustotal,
)
from extractor import IOC_TYPES, extract_iocs

# AbuseIPDB documents no per-minute limit; a few threads are enough.
ABUSEIPDB_MAX_WORKERS = 5

parser = argparse.ArgumentParser(
    description=(
        "Extract IOCs (IPs, URLs, domains, and hashes) from a text file. "
        "Public IPs are checked in AbuseIPDB and VirusTotal. "
        "URLs, domains, and hashes are checked in VirusTotal only."
    )
)
parser.add_argument("input_file", help="path to the input text file")
parser.add_argument(
    "-t",
    "--types",
    nargs="+",
    choices=IOC_TYPES,
    default=IOC_TYPES,
    metavar="TYPE",
    help=f"IOC types to show and check: {', '.join(IOC_TYPES)} (default: all)",
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

# Non-public IPs have no reputation data; don't waste requests.
public_ips = [ip for ip in iocs["valid_ips"] if ip.is_global]

should_check_ips = "ips" in args.types and bool(public_ips)

virustotal_lookups = []
if should_check_ips:
    virustotal_lookups += [("ips", str(ip)) for ip in public_ips]
if "urls" in args.types:
    virustotal_lookups += [("urls", url) for url in iocs["urls"]]
if "domains" in args.types:
    virustotal_lookups += [("domains", domain) for domain in iocs["domains"]]
if "hashes" in args.types:
    for hashes in iocs["hashes"].values():
        virustotal_lookups += [("hashes", hash_value) for hash_value in hashes]

load_dotenv()
abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")
virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")

cache = load_cache()

if should_check_ips and not abuseipdb_api_key:
    print(
        "warning: ABUSEIPDB_API_KEY is not set, skipping AbuseIPDB lookups. "
        "To enable them, add your API key to .env (see .env.example).",
        file=sys.stderr,
    )

if should_check_ips and abuseipdb_api_key:
    print("\nAbuseIPDB results:")
    start_time = time.perf_counter()

    # Requests run in threads; their errors are raised by result() below.
    with ThreadPoolExecutor(max_workers=ABUSEIPDB_MAX_WORKERS) as executor:
        futures = [
            executor.submit(check_ip_abuseipdb, str(ip), abuseipdb_api_key)
            for ip in public_ips
        ]

    for ip, future in zip(public_ips, futures):
        # 401, 429 and connection errors repeat for every IP, so exit.
        # Other errors may only affect this IP, so skip it.
        try:
            abuseipdb_result = future.result()
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

if virustotal_lookups and not virustotal_api_key:
    print(
        "warning: VIRUSTOTAL_API_KEY is not set, skipping VirusTotal lookups. "
        "To enable them, add your API key to .env (see .env.example).",
        file=sys.stderr,
    )

if virustotal_lookups and virustotal_api_key:
    print("\nVirusTotal results:")
    virustotal_cache = cache.setdefault("virustotal", {})
    requests_sent = 0
    start_time = time.perf_counter()
    for ioc_type, ioc_value in virustotal_lookups:
        type_cache = virustotal_cache.setdefault(ioc_type, {})

        if requests_sent > 0:
            time.sleep(VIRUSTOTAL_REQUEST_INTERVAL_SECONDS)
        requests_sent += 1

        # 401, 429 and connection errors repeat for every IOC, so exit.
        # Other errors may only affect this IOC, so skip it.
        try:
            virustotal_result = check_virustotal(
                ioc_type,
                ioc_value,
                virustotal_api_key,
            )
        except requests.HTTPError as error:
            status_code = error.response.status_code
            if status_code == 401:
                sys.exit(
                    "error: VirusTotal rejected the API key (HTTP 401). "
                    "Check VIRUSTOTAL_API_KEY in .env."
                )
            elif status_code == 404:
                analysis_stats = None
            elif status_code == 429:
                sys.exit(
                    "error: VirusTotal request limit reached (HTTP 429). "
                    "The daily limit (500) is probably used up. "
                    "Try again tomorrow."
                )
            elif 500 <= status_code <= 599:
                print(
                    f"{ioc_value} --- not checked: VirusTotal server error "
                    f"(HTTP {status_code})"
                )
                continue
            else:
                print(
                    f"{ioc_value} --- not checked: request failed "
                    f"(HTTP {status_code})"
                )
                continue
        except requests.Timeout:
            print(f"{ioc_value} --- not checked: no response in time")
            continue
        except requests.ConnectionError:
            sys.exit(
                "error: cannot connect to VirusTotal. "
                "Check your internet connection."
            )
        else:
            analysis_stats = virustotal_result["last_analysis_stats"]

        # Errors never get here; only results and "not found" are cached.
        type_cache[ioc_value] = {
            "analysis_stats": analysis_stats,
            "checked_at": current_timestamp(),
        }
        save_cache(cache)

        if analysis_stats is None:
            print(f"{ioc_value} --- not found in VirusTotal")
            continue

        malicious_count = analysis_stats["malicious"]
        suspicious_count = analysis_stats["suspicious"]
        engine_count = sum(analysis_stats.values())
        print(
            f"{ioc_value} --- malicious: {malicious_count}/{engine_count}, "
            f"suspicious: {suspicious_count}"
        )

    elapsed_seconds = time.perf_counter() - start_time
    print(
        f"\nVirusTotal lookups: {len(virustotal_lookups)} "
        f"in {elapsed_seconds:.2f} s"
    )
