# IOC Enricher

A command-line tool that extracts Indicators of Compromise (IOCs) from text and checks their reputation using public threat intelligence APIs.

I'm building it as a learning project to practice Python and Git on a problem that comes up in Blue Team work: IOCs in reports and emails are often defanged (e.g. `hxxp://evil[.]com`), so they can't be pasted straight into other tools.

> **Status:** Early development. Nothing below is implemented yet.

## Planned features

- Extract IPv4 addresses, domains, URLs and file hashes (MD5, SHA1, SHA256) from text
- Handle defanged indicators
- Look up reputation in AbuseIPDB and VirusTotal
- Print results in the terminal and save them to JSON or CSV
