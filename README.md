# IOC Enricher

A command-line tool that extracts Indicators of Compromise (IOCs) from text and checks their reputation in AbuseIPDB and VirusTotal.

I'm building it as a learning project to practice Python and Git on a problem that comes up in Blue Team work: IOCs in reports and emails are often defanged (e.g. `hxxp://evil[.]com`), so they can't be pasted straight into other tools, and each one still has to be checked by hand.

> **Status:** work in progress after v0.2. IOC extraction, AbuseIPDB lookups for public IPv4 addresses, and VirusTotal lookups for all IOC types work. Caching and saving results to a file are not implemented yet.

## What it does

- Extracts IPv4 addresses, URLs, domains, and file hashes (MD5, SHA1, SHA256) from a text file.
- Refangs defanged indicators before extraction (`hxxp`, `[.]`, `[:]`).
- Validates IPv4 addresses and labels them as public or non-public (private, loopback, documentation ranges).
- Skips matches that look like file names (e.g. `report.pdf`) in domain results.
- Removes duplicates and sorts the results.
- Checks public IPv4 addresses in AbuseIPDB and shows their abuse confidence score (0-100), based on reports from the last 90 days. Up to 5 addresses are checked at the same time.
- Checks public IPv4 addresses, URLs, domains, and hashes in VirusTotal and shows how many engines flagged each one as malicious (out of all engines that analyzed it) and how many as suspicious. IOCs that VirusTotal has no data on are reported as "not found in VirusTotal".
- Waits 15 seconds between VirusTotal requests to stay within the free API limit of 4 requests per minute.
- Non-public IP addresses are not sent to either API.
- If an API key is missing, prints a warning and skips that service. Stops with a clear message if a key is rejected, the daily limit is reached, or there is no connection. If a single lookup fails (server error, timeout), that IOC is marked as not checked and the rest are still checked.
- Shows how long the lookups took.

## Requirements

- Python 3 (tested with Python 3.14).
- The packages in `requirements.txt` (`requests`, `python-dotenv`).
- Optional: a free [AbuseIPDB](https://www.abuseipdb.com/) account and API key. The free plan allows 1,000 checks per day.
- Optional: a free [VirusTotal](https://www.virustotal.com/) account and API key. The free public API allows 4 requests per minute and 500 per day and must not be used in commercial products or services.

Without an API key, the tool still extracts IOCs and skips the lookups for that service.

## Setup

```
git clone https://github.com/n1cebot/ioc-enricher.git
cd ioc-enricher
python -m venv .venv
```

Activate the virtual environment:

```
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Linux / macOS
source .venv/bin/activate
```

Install the dependencies:

```
python -m pip install -r requirements.txt
```

Copy `.env.example` to `.env` and put your API keys after the `=` signs:

```
ABUSEIPDB_API_KEY=your_abuseipdb_key
VIRUSTOTAL_API_KEY=your_virustotal_key
```

`.env` is listed in `.gitignore`, so the keys stay on your machine.

## Usage

```
python main.py sample.txt
```

Show and check only selected IOC types (separate them with spaces):

```
python main.py sample.txt --types ips hashes
```

Available types: `ips`, `urls`, `domains`, `hashes`. Run `python main.py -h` for all options.

Only the selected types are looked up. Public IPs are checked in AbuseIPDB and VirusTotal. URLs, domains, and hashes are checked in VirusTotal only.

Because of the 15-second wait, VirusTotal lookups take about 15 seconds per IOC. A full run on `sample.txt` sends 17 requests to VirusTotal and takes about 4 minutes, so `--types` is useful for quick checks.

Example output for `python main.py sample.txt --types ips`:

```
Skipping invalid IP address: 999.1.1.1

IP addresses:
1.1.1.1 --- public
8.8.8.8 --- public
10.0.0.5 --- non-public
192.168.1.10 --- non-public
198.51.100.7 --- non-public
203.0.113.45 --- non-public
203.0.113.99 --- non-public

AbuseIPDB results:
1.1.1.1 --- abuse confidence score: 0/100
8.8.8.8 --- abuse confidence score: 0/100

AbuseIPDB lookups: 2 in 0.87 s

VirusTotal results:
1.1.1.1 --- malicious: 1/92, suspicious: 0
8.8.8.8 --- malicious: 1/92, suspicious: 0

VirusTotal lookups: 2 in 16.04 s
```

Example output for `python main.py sample.txt --types hashes`:

```
Hashes:
MD5
44d88612fea8a8f36de82e1278abb02f
SHA1
3395856ce81f2b7382dee72602f798b642f14140
SHA256
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

VirusTotal results:
44d88612fea8a8f36de82e1278abb02f --- malicious: 65/74, suspicious: 0
3395856ce81f2b7382dee72602f798b642f14140 --- malicious: 65/74, suspicious: 0
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f --- malicious: 65/74, suspicious: 0

VirusTotal lookups: 3 in 31.89 s
```

A few things to keep in mind when reading the results:

- VirusTotal results change over time, so the numbers above may differ when you run it.
- A single detection on a well-known address (like `1/92` for `8.8.8.8`) is most likely a false positive, which is why the tool always shows the total number of engines.
- VirusTotal only has data on URLs that someone has submitted before. This tool does not submit anything, so new URLs show up as "not found in VirusTotal".

`sample.txt` is a fictional report with test data. It only contains documentation IP ranges, `example` domains, well-known public DNS resolvers, and the hashes of the harmless EICAR test file (which is why the hashes get so many detections).

## Project structure

- `main.py` - command-line interface
- `extractor.py` - IOC extraction and refanging
- `enrich.py` - AbuseIPDB and VirusTotal lookups
- `sample.txt` - sample input for testing
- `requirements.txt` - Python dependencies
- `.env.example` - template for the `.env` file with the API keys

## Planned

- Cache results to avoid repeated requests
- Save results to JSON or CSV
