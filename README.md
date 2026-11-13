# IOC Enricher

A command-line tool that extracts Indicators of Compromise (IOCs) from text. Checking their reputation with public threat intelligence APIs is planned next.

I'm building it as a learning project to practice Python and Git on a problem that comes up in Blue Team work: IOCs in reports and emails are often defanged (e.g. `hxxp://evil[.]com`), so they can't be pasted straight into other tools.

> **Status:** v0.1. IOC extraction works. Reputation lookups are not implemented yet.

## What it does

- Extracts IPv4 addresses, URLs, domains and file hashes (MD5, SHA1, SHA256) from a text file
- Refangs defanged indicators before extraction (`hxxp`, `[.]`, `[:]`)
- Validates IPv4 addresses and labels them as public or non-public (private, loopback, documentation ranges)
- Skips matches that look like file names (e.g. `report.pdf`) in domain results
- Removes duplicates and sorts the results

## Requirements

Python 3 (tested with Python 3.14). Only the standard library is used, so there is nothing to install.

## Usage

```
git clone https://github.com/n1cebot/ioc-enricher.git
cd ioc-enricher
python main.py sample.txt
```

Show only selected IOC types (separate them with spaces):

```
python main.py sample.txt --types ips hashes
```

Available types: `ips`, `urls`, `domains`, `hashes`. Run `python main.py -h` for all options.

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
```

`sample.txt` is a fictional report with test data. It only contains documentation IP ranges, `example` domains, well-known public DNS resolvers and the hashes of the harmless EICAR test file.

## Project structure

- `main.py` - command-line interface
- `extractor.py` - IOC extraction and refanging
- `sample.txt` - sample input for testing

## Planned

- Look up reputation in AbuseIPDB and VirusTotal
- Save results to JSON or CSV
