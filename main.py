import ipaddress
import re


input_path = "sample.txt"

with open(input_path, encoding="utf-8") as f:
    text = f.read()

# Find IPv4 candidates: four dot-separated groups of 1-3 digits.
# Values like 999.1.1.1 still match here; they are validated below.
ip_matches = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
ip_candidates = set(ip_matches)

valid_ips = []
for candidate in ip_candidates:
    try:
        valid_ips.append(ipaddress.ip_address(candidate))
    except ValueError:
        # The regex also matches strings that only look like IPs,
        # such as 999.1.1.1. ip_address() raises ValueError for them,
        # e.g. when an octet exceeds 255.
        print(f"Skipping invalid IP address: {candidate}")

print("\nValid IP addresses:")
for ip in sorted(valid_ips):
    # is_global is False not only for private ranges (RFC 1918),
    # but also for loopback and documentation ranges (RFC 5737).
    if ip.is_global:
        print(f"{ip} --- public")
    else:
        print(f"{ip} --- non-public")
