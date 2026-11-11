import ipaddress
import re


REFANG_REPLACEMENTS = {"hxxp": "http", r"\[\.\]": ".", r"\[:\]": ":"}

# File extensions that are not TLDs, so a match such as report.pdf
# can be dropped from domain results. Extensions that are also real
# TLDs (e.g. zip, mov, py, pl) are left out on purpose.
FILE_EXTENSIONS = {"exe", "dll", "msi", "bat", "ps1", "vbs", "js",
                   "pdf", "doc", "docx", "xlsx", "txt", "lnk", "iso"}

HASH_LENGTHS = {"MD5": 32, "SHA1": 40, "SHA256": 64}


def refang_text(text):
    """Return text with defanged IOCs restored to their normal form."""
    for defanged, normal in REFANG_REPLACEMENTS.items():
        text = re.sub(defanged, normal, text, flags=re.IGNORECASE)
    return text


def extract_ips(text):
    """Return valid and invalid IPv4 addresses found in text.

    Valid addresses are returned as sorted IPv4Address objects,
    invalid candidates (e.g. 999.1.1.1) as a sorted list of strings.
    """
    # Find IPv4 candidates: four dot-separated groups of 1-3 digits.
    # Values like 999.1.1.1 still match here; they are validated below.
    ip_matches = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
    ip_candidates = set(ip_matches)

    valid_ips = []
    invalid_ips = []
    for candidate in ip_candidates:
        try:
            valid_ips.append(ipaddress.ip_address(candidate))
        except ValueError:
            # The regex also matches strings that only look like IPs,
            # such as 999.1.1.1. ip_address() raises ValueError
            # for them, e.g. when an octet exceeds 255.
            invalid_ips.append(candidate)
    return sorted(valid_ips), sorted(invalid_ips)


def extract_urls(text):
    """Return a sorted list of unique http/https URLs found in text."""
    # Match http/https URLs up to the next whitespace. The trailing \b
    # drops sentence punctuation such as a final period.
    # Defanged URLs (hxxp://, [.]) must be refanged first to match.
    url_matches = re.findall(r"\bhttps?://\S+\b", text, re.IGNORECASE)
    return sorted(set(url_matches))


def extract_domains(text):
    """Return a sorted list of unique domain names found in text.

    Matches ending with a common file extension (e.g. report.pdf)
    are skipped, since they are file names rather than domains.
    """
    # Match domains: dot-separated labels of letters, digits or
    # hyphens, ending with a letters-only TLD, so IP addresses are
    # not matched.
    domain_matches = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)
    domains = []
    for match in domain_matches:
        suffix = match.rsplit(".", 1)[-1]
        if suffix.lower() not in FILE_EXTENSIONS:
            domains.append(match)
    return sorted(set(domains))


def extract_hashes(text):
    """Return lowercase hashes found in text, grouped by type."""
    hashes_by_type = {}
    # Hashes are identified by length only. The \b anchors ensure an
    # exact length, so a SHA256 is not also reported as an MD5 or SHA1.
    for hash_type, length in HASH_LENGTHS.items():
        hash_pattern = rf"\b[a-fA-F0-9]{{{length}}}\b"
        hash_matches = [h.lower() for h in re.findall(hash_pattern, text)]
        hashes_by_type[hash_type] = sorted(set(hash_matches))
    return hashes_by_type


def extract_iocs(raw_text):
    """Refang text and return all IOCs found in it.

    Keys: "valid_ips", "invalid_ips", "urls", "domains" and "hashes".
    Hashes are grouped by type (MD5, SHA1, SHA256).
    """
    # Refang IOCs (e.g. evil[.]com -> evil.com) so the regexes can match
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
    # is_global is False not only for private ranges (RFC 1918),
    # but also for loopback and documentation ranges (RFC 5737).
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
