# Vulnerability: Psalm Configuration Exposure - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`psalm-config.yaml`)

## Description
Psalm configuration page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/psalm.xml
```

