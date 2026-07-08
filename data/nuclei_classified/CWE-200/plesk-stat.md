# Vulnerability: Webalizer Log Analyzer Configuration - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`plesk-stat.yaml`)

## Description
Webalizer log analyzer configuration was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/plesk-stat/
```

