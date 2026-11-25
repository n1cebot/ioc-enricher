"""Extract IOCs from a text file and look up their reputation.

Public IPs are checked in AbuseIPDB and VirusTotal. URLs, domains, and
hashes are checked in VirusTotal only.
"""

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests
from dotenv import load_dotenv

from cache import current_timestamp, is_fresh, load_cache, save_cache
from enrich import (
    VIRUSTOTAL_REQUEST_INTERVAL_SECONDS,
    check_ip_abuseipdb,
    check_virustotal,
)
from extractor import IOC_TYPES, extract_iocs

# AbuseIPDB documents no per-minute limit; a few threads are enough.
ABUSEIPDB_MAX_WORKERS = 5


def format_abuseipdb_cell(entry):
    """Return the ABUSEIPDB table cell for one AbuseIPDB entry.

    Return "-" if entry is None, "not checked: <reason>" if the lookup
    failed, and the score out of 100 otherwise. Cached results end
    with "(cached)".
    """
    if entry is None:
        return "-"
    not_checked_reason = entry["not_checked_reason"]
    if not_checked_reason is not None:
        return f"not checked: {not_checked_reason}"

    abuse_score = entry["abuse_confidence_score"]
    cell_text = f"{abuse_score}/100"
    if entry["cached"]:
        cell_text += " (cached)"
    return cell_text


def format_virustotal_cell(entry):
    """Return the VIRUSTOTAL table cell for one VirusTotal entry.

    Return "-" if entry is None, "not checked: <reason>" if the lookup
    failed, "not found" if VirusTotal has no report, and the malicious
    and suspicious counts otherwise. Cached results end with "(cached)".
    """
    if entry is None:
        return "-"
    not_checked_reason = entry["not_checked_reason"]
    if not_checked_reason is not None:
        return f"not checked: {not_checked_reason}"

    analysis_stats = entry["analysis_stats"]
    if analysis_stats is None:
        cell_text = "not found"
    else:
        malicious_count = analysis_stats["malicious"]
        suspicious_count = analysis_stats["suspicious"]
        engine_count = sum(analysis_stats.values())
        cell_text = (
            f"{malicious_count}/{engine_count} malicious, "
            f"{suspicious_count} suspicious"
        )
    if entry["cached"]:
        cell_text += " (cached)"
    return cell_text


def abuseipdb_csv_fields(entry):
    """Return the CSV fields for one AbuseIPDB entry.

    Return the score and a status: "checked", "cached", or
    "not checked: <reason>". Both fields are empty if entry is None.
    """
    if entry is None:
        return ["", ""]
    not_checked_reason = entry["not_checked_reason"]
    if not_checked_reason is not None:
        return ["", f"not checked: {not_checked_reason}"]

    abuse_score = entry["abuse_confidence_score"]
    status = "cached" if entry["cached"] else "checked"
    return [abuse_score, status]


def virustotal_csv_fields(entry):
    """Return the CSV fields for one VirusTotal entry.

    Return the malicious, suspicious, and engine counts and a status:
    "checked", "cached", "not found", "not found (cached)", or
    "not checked: <reason>". The counts are empty if there is no
    report, and all fields are empty if entry is None.
    """
    if entry is None:
        return ["", "", "", ""]
    not_checked_reason = entry["not_checked_reason"]
    if not_checked_reason is not None:
        return ["", "", "", f"not checked: {not_checked_reason}"]

    analysis_stats = entry["analysis_stats"]
    if analysis_stats is None:
        status = "not found (cached)" if entry["cached"] else "not found"
        return ["", "", "", status]

    malicious_count = analysis_stats["malicious"]
    suspicious_count = analysis_stats["suspicious"]
    engine_count = sum(analysis_stats.values())
    status = "cached" if entry["cached"] else "checked"
    return [malicious_count, suspicious_count, engine_count, status]


def print_table(headers, rows):
    """Print rows as a table with a header and aligned columns.

    Each row is a list of strings, one for each header. Every column is
    as wide as its longest value or header, and columns are separated
    by two spaces.
    """
    column_widths = [len(header) for header in headers]
    for row in rows:
        for column_index, cell in enumerate(row):
            column_widths[column_index] = max(
                column_widths[column_index],
                len(cell),
            )

    padded_headers = [
        f"{header:<{width}}" for header, width in zip(headers, column_widths)
    ]
    header_line = "  ".join(padded_headers).rstrip()
    print(header_line)

    dashes = ["-" * width for width in column_widths]
    dash_line = "  ".join(dashes)
    print(dash_line)

    for row in rows:
        padded_cells = [
            f"{cell:<{width}}" for cell, width in zip(row, column_widths)
        ]
        row_line = "  ".join(padded_cells).rstrip()
        print(row_line)


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
parser.add_argument(
    "-o",
    "--output",
    metavar="FILE",
    help="also save the results to FILE as JSON (must end with .json)",
)
args = parser.parse_args()

if args.output is not None and not args.output.lower().endswith(".json"):
    parser.error(
        f"unsupported output file: {args.output} "
        "(use a name ending with .json)"
    )

try:
    with open(args.input_file, encoding="utf-8") as f:
        raw_text = f.read()
except OSError as error:
    parser.error(f"cannot read {args.input_file}: {error.strerror}")
except UnicodeDecodeError:
    parser.error(f"{args.input_file} is not a UTF-8 text file")

iocs = extract_iocs(raw_text)

# Every extracted IOC gets an entry; lookups replace None with results.
results = {}

if "ips" in args.types:
    for invalid_ip in iocs["invalid_ips"]:
        print(
            f"warning: skipping invalid IP address: {invalid_ip}",
            file=sys.stderr,
        )

    results["ips"] = {}
    for ip in iocs["valid_ips"]:
        results["ips"][str(ip)] = {
            "scope": "public" if ip.is_global else "non-public",
            "abuseipdb": None,
            "virustotal": None,
        }

if "urls" in args.types:
    results["urls"] = {}
    for url in iocs["urls"]:
        results["urls"][url] = {"virustotal": None}

if "domains" in args.types:
    results["domains"] = {}
    for domain in iocs["domains"]:
        results["domains"][domain] = {"virustotal": None}

if "hashes" in args.types:
    results["hashes"] = {}
    for hash_type, hashes in iocs["hashes"].items():
        for hash_value in hashes:
            results["hashes"][hash_value] = {
                "hash_type": hash_type,
                "virustotal": None,
            }

# Non-public IPs have no reputation data; don't waste requests.
public_ips = [str(ip) for ip in iocs["valid_ips"] if ip.is_global]

should_check_ips = "ips" in args.types and bool(public_ips)

virustotal_lookups = []
if should_check_ips:
    virustotal_lookups += [("ips", ip) for ip in public_ips]
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
    print(f"Looking up {len(public_ips)} IPs in AbuseIPDB...", file=sys.stderr)
    abuseipdb_cache = cache.setdefault("abuseipdb", {})
    abuseipdb_ip_cache = abuseipdb_cache.setdefault("ips", {})
    start_time = time.perf_counter()

    # Only IPs without a fresh cached result are sent to the threads.
    fresh_entries = {}
    ips_to_check = []
    for ip in public_ips:
        cached_entry = abuseipdb_ip_cache.get(ip)
        if cached_entry is not None and is_fresh(cached_entry["checked_at"]):
            fresh_entries[ip] = cached_entry
        else:
            ips_to_check.append(ip)

    # Requests run in threads; their errors are raised by result() below.
    with ThreadPoolExecutor(max_workers=ABUSEIPDB_MAX_WORKERS) as executor:
        futures = {
            ip: executor.submit(check_ip_abuseipdb, ip, abuseipdb_api_key)
            for ip in ips_to_check
        }

    reported_errors = set()
    for ip in public_ips:
        if ip in fresh_entries:
            abuse_score = fresh_entries[ip]["abuse_confidence_score"]
            results["ips"][ip]["abuseipdb"] = {
                "abuse_confidence_score": abuse_score,
                "cached": True,
                "not_checked_reason": None,
            }
            continue

        not_checked_reason = None

        # 401, 429 and connection errors repeat for every IP,
        # so explain each of them only once.
        # Other errors may only affect this IP, so skip it.
        try:
            abuseipdb_result = futures[ip].result()
        except requests.HTTPError as error:
            status_code = error.response.status_code
            if status_code == 401:
                if "key_rejected" not in reported_errors:
                    print(
                        "error: AbuseIPDB rejected the API key (HTTP 401). "
                        "Check ABUSEIPDB_API_KEY in .env.",
                        file=sys.stderr,
                    )
                    reported_errors.add("key_rejected")
                not_checked_reason = "API key rejected (HTTP 401)"
            elif status_code == 429:
                if "limit_reached" not in reported_errors:
                    print(
                        "error: AbuseIPDB daily request limit reached "
                        "(HTTP 429). Try again tomorrow.",
                        file=sys.stderr,
                    )
                    reported_errors.add("limit_reached")
                not_checked_reason = "daily limit reached (HTTP 429)"
            elif 500 <= status_code <= 599:
                not_checked_reason = (
                    f"AbuseIPDB server error (HTTP {status_code})"
                )
            else:
                not_checked_reason = f"request failed (HTTP {status_code})"
        except requests.Timeout:
            not_checked_reason = "no response in time"
        except requests.ConnectionError:
            if "no_connection" not in reported_errors:
                print(
                    "error: cannot connect to AbuseIPDB. "
                    "Check your internet connection.",
                    file=sys.stderr,
                )
                reported_errors.add("no_connection")
            not_checked_reason = "no connection"

        if not_checked_reason is not None:
            results["ips"][ip]["abuseipdb"] = {
                "abuse_confidence_score": None,
                "cached": False,
                "not_checked_reason": not_checked_reason,
            }
            continue

        abuse_score = abuseipdb_result["abuseConfidenceScore"]

        # Errors never get here; only results are cached.
        abuseipdb_ip_cache[ip] = {
            "abuse_confidence_score": abuse_score,
            "checked_at": current_timestamp(),
        }
        save_cache(cache)

        results["ips"][ip]["abuseipdb"] = {
            "abuse_confidence_score": abuse_score,
            "cached": False,
            "not_checked_reason": None,
        }

    elapsed_seconds = time.perf_counter() - start_time
    print(
        f"AbuseIPDB lookups: {len(public_ips)} in {elapsed_seconds:.2f} s",
        file=sys.stderr,
    )

if virustotal_lookups and not virustotal_api_key:
    print(
        "warning: VIRUSTOTAL_API_KEY is not set, skipping VirusTotal lookups. "
        "To enable them, add your API key to .env (see .env.example).",
        file=sys.stderr,
    )

if virustotal_lookups and virustotal_api_key:
    print(
        f"Looking up {len(virustotal_lookups)} IOCs in VirusTotal "
        "(about 15 s per request)...",
        file=sys.stderr,
    )
    virustotal_cache = cache.setdefault("virustotal", {})
    requests_sent = 0
    virustotal_stopped = False
    start_time = time.perf_counter()
    for ioc_type, ioc_value in virustotal_lookups:
        type_cache = virustotal_cache.setdefault(ioc_type, {})

        # A fresh cached result skips both the request and the wait.
        cached_entry = type_cache.get(ioc_value)
        if cached_entry is not None and is_fresh(cached_entry["checked_at"]):
            analysis_stats = cached_entry["analysis_stats"]
            results[ioc_type][ioc_value]["virustotal"] = {
                "analysis_stats": analysis_stats,
                "cached": True,
                "not_checked_reason": None,
            }
            continue

        # After a 401, 429 or connection error, send no more requests.
        if virustotal_stopped:
            results[ioc_type][ioc_value]["virustotal"] = {
                "analysis_stats": None,
                "cached": False,
                "not_checked_reason": "VirusTotal lookups stopped",
            }
            continue

        if requests_sent > 0:
            time.sleep(VIRUSTOTAL_REQUEST_INTERVAL_SECONDS)
        requests_sent += 1

        not_checked_reason = None

        # 401, 429 and connection errors repeat for every IOC,
        # so stop sending requests.
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
                print(
                    "error: VirusTotal rejected the API key (HTTP 401). "
                    "Check VIRUSTOTAL_API_KEY in .env. "
                    "Skipping the remaining VirusTotal lookups.",
                    file=sys.stderr,
                )
                virustotal_stopped = True
                not_checked_reason = "API key rejected (HTTP 401)"
            elif status_code == 404:
                analysis_stats = None
            elif status_code == 429:
                print(
                    "error: VirusTotal request limit reached (HTTP 429). "
                    "The daily limit (500) is probably used up. "
                    "Try again tomorrow. "
                    "Skipping the remaining VirusTotal lookups.",
                    file=sys.stderr,
                )
                virustotal_stopped = True
                not_checked_reason = "request limit reached (HTTP 429)"
            elif 500 <= status_code <= 599:
                not_checked_reason = (
                    f"VirusTotal server error (HTTP {status_code})"
                )
            else:
                not_checked_reason = f"request failed (HTTP {status_code})"
        except requests.Timeout:
            not_checked_reason = "no response in time"
        except requests.ConnectionError:
            print(
                "error: cannot connect to VirusTotal. "
                "Check your internet connection. "
                "Skipping the remaining VirusTotal lookups.",
                file=sys.stderr,
            )
            virustotal_stopped = True
            not_checked_reason = "no connection"
        else:
            analysis_stats = virustotal_result["last_analysis_stats"]

        if not_checked_reason is not None:
            results[ioc_type][ioc_value]["virustotal"] = {
                "analysis_stats": None,
                "cached": False,
                "not_checked_reason": not_checked_reason,
            }
            continue

        # Errors never get here; only results and "not found" are cached.
        type_cache[ioc_value] = {
            "analysis_stats": analysis_stats,
            "checked_at": current_timestamp(),
        }
        save_cache(cache)

        results[ioc_type][ioc_value]["virustotal"] = {
            "analysis_stats": analysis_stats,
            "cached": False,
            "not_checked_reason": None,
        }

    elapsed_seconds = time.perf_counter() - start_time
    print(
        f"VirusTotal lookups: {len(virustotal_lookups)} "
        f"in {elapsed_seconds:.2f} s",
        file=sys.stderr,
    )

tables = []

if results.get("ips"):
    ip_rows = []
    for ip, ip_result in results["ips"].items():
        ip_rows.append([
            ip,
            ip_result["scope"],
            format_abuseipdb_cell(ip_result["abuseipdb"]),
            format_virustotal_cell(ip_result["virustotal"]),
        ])
    tables.append((["IP", "SCOPE", "ABUSEIPDB", "VIRUSTOTAL"], ip_rows))

if results.get("urls"):
    url_rows = []
    for url, url_result in results["urls"].items():
        url_rows.append([
            url,
            format_virustotal_cell(url_result["virustotal"]),
        ])
    tables.append((["URL", "VIRUSTOTAL"], url_rows))

if results.get("domains"):
    domain_rows = []
    for domain, domain_result in results["domains"].items():
        domain_rows.append([
            domain,
            format_virustotal_cell(domain_result["virustotal"]),
        ])
    tables.append((["DOMAIN", "VIRUSTOTAL"], domain_rows))

if results.get("hashes"):
    hash_rows = []
    for hash_value, hash_result in results["hashes"].items():
        hash_rows.append([
            hash_value,
            hash_result["hash_type"],
            format_virustotal_cell(hash_result["virustotal"]),
        ])
    tables.append((["HASH", "TYPE", "VIRUSTOTAL"], hash_rows))

# Blank line on stderr, so redirected output starts with a table.
print(file=sys.stderr)
for table_index, (headers, rows) in enumerate(tables):
    if table_index > 0:
        print()
    print_table(headers, rows)

if args.output is not None:
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    except OSError as error:
        sys.exit(f"\nerror: cannot write {args.output}: {error.strerror}")
    print(f"\nResults saved to {args.output}", file=sys.stderr)

for url, url_result in results["urls"].items():
    print(url, virustotal_csv_fields(url_result["virustotal"]))
