# Vulnerability: SentinelOne Management Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sentinelone-console.yaml`)

## Description
SentinelOne Management Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

