# Vulnerability: HTTP Missing Security Headers
**Classification:** CWE-693
**Source:** Nuclei Template (`http-missing-security-headers.yaml`)

## Description
This template searches for missing HTTP security headers. The impact of these missing headers can vary.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

