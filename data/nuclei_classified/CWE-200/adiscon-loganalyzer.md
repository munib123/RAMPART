# Vulnerability: Adiscon LogAnalyzer - Information Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`adiscon-loganalyzer.yaml`)

## Description
Adiscon LogAnalyzer was discovered. Adiscon LogAnalyzer is a web interface to syslog and other network event data. It provides easy browsing and analysis of real-time network events and reporting services.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

