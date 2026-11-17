# IOC Enricher

A command-line tool that extracts Indicators of Compromise (IOCs) from text and checks public IP addresses in AbuseIPDB. Lookups for the other IOC types (via VirusTotal) are planned next.

I'm building it as a learning project to practice Python and Git on a problem that comes up in Blue Team work: IOCs in reports and emails are often defanged (e.g. `hxxp://evil[.]com`), so they can't be pasted straight into other tools, and each one still has to be checked by hand.

> **Status:** v0.2. IOC extraction and AbuseIPDB lookups for public IPv4 addresses work. Other lookups and saving results to a file are not implemented yet.

## What it does

- Extracts IPv4 addresses, URLs, domains and file hashes (MD5, SHA1, SHA256) from a text file
- Refangs defanged indicators before extraction (`hxxp`, `[.]`, `[:]`)
- Validates IPv4 addresses and labels them as public or non-public (private, loopback, documentation ranges)
- Skips matches that look like file names (e.g. `report.pdf`) in domain results
- Removes duplicates and sorts the results
- Checks public IPv4 addresses in AbuseIPDB and shows their abuse confidence score (0-100), based on reports from the last 90 days. Non-public addresses are not sent to the API.
- Stops with a clear message if the API key is missing or rejected, the daily limit is reached or there is no connection. If a single lookup fails (server error, timeout), that IP is marked as not checked and the rest are still checked.
- Shows how long the AbuseIPDB lookups took

## Requirements

- Python 3 (tested with Python 3.14)
- The packages in `requirements.txt` (`requests`, `python-dotenv`)
- A free [AbuseIPDB](https://www.abuseipdb.com/) account and API key. The free plan allows 1,000 checks per day.

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

Copy `.env.example` to `.env` and put your AbuseIPDB API key after `ABUSEIPDB_API_KEY=`:

```
ABUSEIPDB_API_KEY=your_key
```

`.env` is listed in `.gitignore`, so the key stays on your machine.

## Usage

```
python main.py sample.txt
```

Show only selected IOC types (separate them with spaces):

```
python main.py sample.txt --types ips hashes
```

Available types: `ips`, `urls`, `domains`, `hashes`. Run `python main.py -h` for all options.

AbuseIPDB is only queried when `ips` is selected (it is by default) and the file contains at least one public IP address. For example, `--types urls hashes` works without an API key.

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

AbuseIPDB lookups: 2 in 0.88 s
```

`sample.txt` is a fictional report with test data. It only contains documentation IP ranges, `example` domains, well-known public DNS resolvers and the hashes of the harmless EICAR test file.

## Project structure

- `main.py` - command-line interface
- `extractor.py` - IOC extraction and refanging
- `enrich.py` - AbuseIPDB lookups
- `sample.txt` - sample input for testing
- `requirements.txt` - Python dependencies
- `.env.example` - template for the `.env` file with the API key

## Planned

- Look up IPs, domains, URLs and hashes in VirusTotal
- Run lookups in parallel and cache results to avoid repeated requests
- Save results to JSON or CSV
