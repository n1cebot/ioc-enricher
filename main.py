import re


input_path = "sample.txt"

with open(input_path, encoding="utf-8") as f:
    text = f.read()

# Find IPv4 candidates: four dot-separated groups of 1-3 digits.
# Values like 999.1.1.1 still match here; validation happens later.
ip_candidates = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
unique_ips = sorted(set(ip_candidates))

print("Unique IP addresses:")
for ip in unique_ips:
    print(ip)
