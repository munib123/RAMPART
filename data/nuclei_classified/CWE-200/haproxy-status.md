# Vulnerability: HAProxy Statistics Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`haproxy-status.yaml`)

## Description
HAProxy statistics page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/haproxy-status
GET {{BaseURL}}/haproxy?stats
```

