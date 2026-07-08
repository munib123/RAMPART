# Vulnerability: Salesforce Tableau Server - Detect
**Classification:** TECH
**Source:** Nuclei Template (`tableau-server-detect.yaml`)

## Description
Detects Salesforce Tableau Server and extracts the buildid.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

