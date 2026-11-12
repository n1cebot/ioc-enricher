import ipaddress
import re


REFANG_REPLACEMENTS = {"hxxp": "http", r"\[\.\]": ".", r"\[:\]": ":"}
HASH_LENGTHS = {"MD5": 32, "SHA1": 40, "SHA256": 64}

# File extensions to drop from domain results.
# Those that are also TLDs (zip, py, pl) are left out.
FILE_EXTENSIONS = {"exe", "dll", "msi", "bat", "ps1", "vbs", "js",
                   "pdf", "doc", "docx", "xlsx", "txt", "lnk", "iso"}


def refang_text(text):
    """Convert defanged IOCs (hxxp, [.], [:]) back to normal form."""
    for defanged, normal in REFANG_REPLACEMENTS.items():
        text = re.sub(defanged, normal, text, flags=re.IGNORECASE)
    return text


def extract_ips(text):
    """Return a (valid, invalid) tuple of IPv4 addresses found in text.

    Valid addresses are IPv4Address objects; invalid ones are raw
    strings that failed validation (e.g. 999.1.1.1).
    """
    # Loose match; the 0-255 range check is done by ipaddress below.
    ip_matches = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
    ip_candidates = set(ip_matches)

    valid_ips = []
    invalid_ips = []
    for candidate in ip_candidates:
        try:
            valid_ips.append(ipaddress.ip_address(candidate))
        except ValueError:
            invalid_ips.append(candidate)
    return sorted(valid_ips), sorted(invalid_ips)


def extract_urls(text):
    """Return a sorted list of unique http/https URLs found in text."""
    # Trailing \b strips sentence punctuation like a final period.
    url_matches = re.findall(r"\bhttps?://\S+\b", text, re.IGNORECASE)
    return sorted(set(url_matches))


def extract_domains(text):
    """Return a sorted list of unique domains found in text.

    Filters out filenames matching FILE_EXTENSIONS (e.g. report.pdf).
    """
    domain_matches = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)
    domains = []
    for match in domain_matches:
        suffix = match.rsplit(".", 1)[-1]
        if suffix.lower() not in FILE_EXTENSIONS:
            domains.append(match)
    return sorted(set(domains))


def extract_hashes(text):
    """Return unique lowercase hashes found in text, grouped by type."""
    hashes_by_type = {}
    # Type is guessed by length. \b keeps longer hashes from also
    # matching as shorter ones (e.g. a SHA256 as two MD5s).
    for hash_type, length in HASH_LENGTHS.items():
        hash_pattern = rf"\b[a-fA-F0-9]{{{length}}}\b"
        hash_matches = [h.lower() for h in re.findall(hash_pattern, text)]
        hashes_by_type[hash_type] = sorted(set(hash_matches))
    return hashes_by_type


def extract_iocs(raw_text):
    """Refang text and return all IOCs found in it as a dict."""
    text = refang_text(raw_text)
    valid_ips, invalid_ips = extract_ips(text)
    urls = extract_urls(text)
    domains = extract_domains(text)
    hashes_by_type = extract_hashes(text)

    return {
        "valid_ips": valid_ips,
        "invalid_ips": invalid_ips,
        "urls": urls,
        "domains": domains,
        "hashes": hashes_by_type,
    }


input_path = "sample.txt"
with open(input_path, encoding="utf-8") as f:
    raw_text = f.read()

iocs = extract_iocs(raw_text)

for invalid_ip in iocs["invalid_ips"]:
    print(f"Skipping invalid IP address: {invalid_ip}")

print("\nIP addresses:")
for ip in iocs["valid_ips"]:
    # is_global is False for private, loopback and documentation IPs.
    if ip.is_global:
        print(f"{ip} --- public")
    else:
        print(f"{ip} --- non-public")

print("\nURLs:")
for url in iocs["urls"]:
    print(url)

print("\nDomains:")
for domain in iocs["domains"]:
    print(domain)

print("\nHashes:")
for hash_type, hashes in iocs["hashes"].items():
    print(hash_type)
    for hash_value in hashes:
        print(hash_value)
