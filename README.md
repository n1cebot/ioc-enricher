# IOC Enricher

A command-line tool that extracts Indicators of Compromise (IOCs) from text and checks their reputation in AbuseIPDB and VirusTotal.

I'm building it as a learning project to practice Python and Git on a problem that comes up in Blue Team work: IOCs in reports and emails are often defanged (e.g. `hxxp://evil[.]com`), so they can't be pasted straight into other tools, and each one still has to be checked by hand.

> **Status:** work in progress. IOC extraction, AbuseIPDB lookups for public IPv4 addresses, VirusTotal lookups for all IOC types, a local cache of lookup results, and saving the results to JSON or CSV work.

## What it does

- Extracts IPv4 addresses, URLs, domains, and file hashes (MD5, SHA1, SHA256) from a text file.
- Refangs defanged indicators before extraction (`hxxp`, `[.]`, `[:]`).
- Validates IPv4 addresses and labels them as public or non-public (private, loopback, documentation ranges).
- Skips matches that look like file names (e.g. `report.pdf`) in domain results.
- Removes duplicates and sorts the results.
- Checks public IPv4 addresses in AbuseIPDB and shows their abuse confidence score (0-100), based on reports from the last 90 days. Up to 5 addresses are checked at the same time.
- Checks public IPv4 addresses, URLs, domains, and hashes in VirusTotal and shows how many engines flagged each one as malicious (out of the engines that gave a verdict) and how many as suspicious. IOCs that VirusTotal has no data on are shown as "not found".
- Waits 15 seconds between VirusTotal requests to stay within the free API limit of 4 requests per minute.
- Saves lookup results to a local cache file and reuses them for 6 hours, so checking the same IOCs again doesn't send new requests. Results taken from the cache are marked with "(cached)".
- Non-public IP addresses are not sent to either API.
- If an API key is missing, prints a warning and skips that service.
- Errors from AbuseIPDB or VirusTotal never stop the tool. If a key is rejected, a request limit is reached, or there is no connection, the error is explained once and the IOCs that couldn't be checked are marked as "not checked". After such an error, no more requests are sent to VirusTotal. If a single lookup fails (server error, timeout), only that IOC is marked as not checked.
- Shows the results as tables, one for each IOC type, and can also save them to a JSON or CSV file.
- Shows how many lookups were sent, taken from the cache, or not checked, and how long they took.

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

Because of the 15-second wait, VirusTotal lookups take about 15 seconds per IOC. The first full run on `sample.txt` sends 17 requests to VirusTotal and takes about 4 minutes. After that, the results are cached, so running it again within 6 hours takes less than a second.

Example output for `python main.py sample.txt` (first run, nothing in the cache):

```
warning: skipping invalid IP address: 999.1.1.1
Looking up 2 IPs in AbuseIPDB...
AbuseIPDB lookups: 2 (2 checked, 0 from cache, 0 not checked) in 0.52 s
Looking up 17 IOCs in VirusTotal (about 15 s per request)...
VirusTotal lookups: 17 (17 checked, 0 from cache, 0 not checked) in 251.72 s

IP            SCOPE       ABUSEIPDB  VIRUSTOTAL
------------  ----------  ---------  ----------------------------
1.1.1.1       public      0/100      1/92 malicious, 0 suspicious
8.8.8.8       public      0/100      1/92 malicious, 0 suspicious
10.0.0.5      non-public  -          -
192.168.1.10  non-public  -          -
198.51.100.7  non-public  -          -
203.0.113.45  non-public  -          -
203.0.113.99  non-public  -          -

URL                                            VIRUSTOTAL
---------------------------------------------  ----------
http://login-secure-update.example.com/verify  not found
http://mixed-case.example.net                  not found
https://cdn.example.net/payload.exe            not found
https://colon.example.com/login                not found
https://files.example.org/download/report.pdf  not found

DOMAIN                           VIRUSTOTAL
-------------------------------  ----------------------------
cdn.example.net                  0/92 malicious, 0 suspicious
colon.example.com                0/92 malicious, 0 suspicious
files.example.org                0/92 malicious, 0 suspicious
login-secure-update.example.com  0/92 malicious, 0 suspicious
malicious-site.example.com       0/92 malicious, 0 suspicious
mixed-case.example.net           0/92 malicious, 0 suspicious
update.example.org               0/92 malicious, 0 suspicious

HASH                                                              TYPE    VIRUSTOTAL
----------------------------------------------------------------  ------  -----------------------------
44d88612fea8a8f36de82e1278abb02f                                  MD5     60/62 malicious, 0 suspicious
3395856ce81f2b7382dee72602f798b642f14140                          SHA1    60/62 malicious, 0 suspicious
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f  SHA256  60/62 malicious, 0 suspicious
```

Non-public IPs are not looked up, so they show `-` in both service columns.

The same command run again within 6 hours shows the same tables, with "(cached)" added to every result:

```
AbuseIPDB lookups: 2 (0 checked, 2 from cache, 0 not checked) in 0.00 s
VirusTotal lookups: 17 (0 checked, 17 from cache, 0 not checked) in 0.00 s
```

The "lookups" lines show how many IOCs were sent to the service, taken from the cache, or not checked because of an error.

Example output with no internet connection, when only `1.1.1.1` was in the cache:

```
Looking up 3 IPs in AbuseIPDB...
error: cannot connect to AbuseIPDB. Check your internet connection.
AbuseIPDB lookups: 3 (0 checked, 1 from cache, 2 not checked) in 0.01 s
Looking up 3 IOCs in VirusTotal (about 15 s per request)...
error: cannot connect to VirusTotal. Check your internet connection. Skipping the remaining VirusTotal lookups.
VirusTotal lookups: 3 (0 checked, 1 from cache, 2 not checked) in 0.00 s

IP        SCOPE   ABUSEIPDB                   VIRUSTOTAL
--------  ------  --------------------------  ---------------------------------------
1.1.1.1   public  0/100 (cached)              1/92 malicious, 0 suspicious (cached)
9.9.9.12  public  not checked: no connection  not checked: no connection
9.9.9.13  public  not checked: no connection  not checked: VirusTotal lookups stopped
```

Warnings, progress messages, and errors are printed to stderr, and the tables to stdout. This means `python main.py sample.txt > results.txt` saves only the tables to the file, while the messages stay in the terminal.

A few things to keep in mind when reading the results:

- VirusTotal results change over time, so the numbers above may differ when you run it.
- The VirusTotal total only counts engines that gave a verdict. Engines that timed out, failed, or don't support the file type are left out, so the total can be lower than the number of engines shown on the VirusTotal website. For example, the EICAR hashes above show `60/62` because VirusTotal also listed 5 engines that timed out and 7 that don't support the file type.
- A single detection on a well-known address (like `1/92` for `8.8.8.8`) is most likely a false positive, which is why the tool always shows the total number of engines.
- VirusTotal only has data on URLs that someone has submitted before. This tool does not submit anything, so new URLs show up as "not found".

`sample.txt` is a fictional report with test data. It only contains documentation IP ranges, `example` domains, well-known public DNS resolvers, and the hashes of the harmless EICAR test file (which is why the hashes get so many detections).

## Saving results to a file

Use `-o` (or `--output`) to save the results to a file as well:

```
python main.py sample.txt -o results.json
python main.py sample.txt -o results.csv
```

The format is chosen by the file extension: `.json` or `.csv`. Other extensions are rejected before any lookups are sent. The tables are still printed, and the file is written after them. An existing file with the same name is overwritten.

### JSON

The results are grouped by IOC type. Each IOC has the data from each service it was looked up in, or `null` if it wasn't looked up (for example, non-public IPs). The beginning of the file for `sample.txt` (second run, so the results come from the cache):

```json
{
  "ips": {
    "1.1.1.1": {
      "scope": "public",
      "abuseipdb": {
        "abuse_confidence_score": 0,
        "cached": true,
        "not_checked_reason": null
      },
      "virustotal": {
        "analysis_stats": {
          "harmless": 57,
          "malicious": 1,
          "suspicious": 0,
          "timeout": 0,
          "undetected": 34
        },
        "cached": true,
        "not_checked_reason": null
      }
    },
    "8.8.8.8": {
      "scope": "public",
      "abuseipdb": {
        "abuse_confidence_score": 0,
        "cached": true,
        "not_checked_reason": null
      },
      "virustotal": {
        "analysis_stats": {
          "harmless": 53,
          "malicious": 1,
          "suspicious": 0,
          "timeout": 0,
          "undetected": 38
        },
        "cached": true,
        "not_checked_reason": null
      }
    },
    "10.0.0.5": {
      "scope": "non-public",
      "abuseipdb": null,
      "virustotal": null
    },
```

`analysis_stats` is the full breakdown returned by VirusTotal, or `null` if VirusTotal has no data on the IOC. `not_checked_reason` explains why an IOC couldn't be checked, and is `null` otherwise.

### CSV

The CSV file has one row per IOC and can be opened in a spreadsheet, for example to sort the IOCs by the number of detections. Cells that don't apply to an IOC are left empty. The file for `sample.txt` (second run, so the results come from the cache):

```
type,value,scope,hash_type,abuseipdb_score,abuseipdb_status,virustotal_malicious,virustotal_suspicious,virustotal_engines,virustotal_status
ips,1.1.1.1,public,,0,cached,1,0,92,cached
ips,8.8.8.8,public,,0,cached,1,0,92,cached
ips,10.0.0.5,non-public,,,,,,,
ips,192.168.1.10,non-public,,,,,,,
ips,198.51.100.7,non-public,,,,,,,
ips,203.0.113.45,non-public,,,,,,,
ips,203.0.113.99,non-public,,,,,,,
urls,http://login-secure-update.example.com/verify,,,,,,,,not found (cached)
urls,http://mixed-case.example.net,,,,,,,,not found (cached)
urls,https://cdn.example.net/payload.exe,,,,,,,,not found (cached)
urls,https://colon.example.com/login,,,,,,,,not found (cached)
urls,https://files.example.org/download/report.pdf,,,,,,,,not found (cached)
domains,cdn.example.net,,,,,0,0,92,cached
domains,colon.example.com,,,,,0,0,92,cached
domains,files.example.org,,,,,0,0,92,cached
domains,login-secure-update.example.com,,,,,0,0,92,cached
domains,malicious-site.example.com,,,,,0,0,92,cached
domains,mixed-case.example.net,,,,,0,0,92,cached
domains,update.example.org,,,,,0,0,92,cached
hashes,44d88612fea8a8f36de82e1278abb02f,,MD5,,,60,0,62,cached
hashes,3395856ce81f2b7382dee72602f798b642f14140,,SHA1,,,60,0,62,cached
hashes,275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,,SHA256,,,60,0,62,cached
```

The status columns say where each result came from:

- `abuseipdb_status`: `checked`, `cached`, or `not checked: <reason>`.
- `virustotal_status`: `checked`, `cached`, `not found`, `not found (cached)`, or `not checked: <reason>`.

## Cache

Lookup results are saved to `lookup_cache.json`. The file is created in the folder you run the command from.

- A cached result is used for 6 hours. After that, the IOC is looked up again.
- "Not found" results from VirusTotal are cached too. Errors (server errors, timeouts, rejected keys) are not, so those IOCs are checked again on the next run.
- Cached results are shown even when a service can't be reached, so IOCs checked in the last 6 hours can also be looked up offline.
- Old entries are not removed from the file. They're just not used after 6 hours. To clear the cache, delete `lookup_cache.json`.

`lookup_cache.json` is listed in `.gitignore`, so it stays on your machine.

## Project structure

- `main.py` - command-line interface, tables, and saving results to a file
- `extractor.py` - IOC extraction and refanging
- `enrich.py` - AbuseIPDB and VirusTotal lookups
- `cache.py` - saving and reading cached lookup results
- `sample.txt` - sample input for testing
- `requirements.txt` - Python dependencies
- `.env.example` - template for the `.env` file with the API keys
