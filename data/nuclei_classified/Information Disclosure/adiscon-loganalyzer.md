# Nuclei Template: Adiscon LogAnalyzer - Information Disclosure
**Template ID:** adiscon-loganalyzer
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`adiscon-loganalyzer.yaml`)

## Vulnerability Information & PoC

## Description
Adiscon LogAnalyzer was discovered. Adiscon LogAnalyzer is a web interface to syslog and other network event data. It provides easy browsing and analysis of real-time network events and reporting services.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

## References
- https://loganalyzer.adiscon.com/
