# Vulnerability: Squid Analysis Report Generator
**Classification:** SARG
**Source:** Nuclei Template (`squid-analysis-report-generator.yaml`)

## Description
SARG is an open source tool that allows you to analyse the squid log files and generates beautiful reports in HTML format with information about users, IP addresses, top accessed sites, total bandwidth usage, elapsed time, downloads, access denied websites, daily reports, weekly reports and monthly reports.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

