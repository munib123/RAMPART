# Vulnerability: VerneMQ Status Page
**Classification:** MISCONFIG
**Source:** Nuclei Template (`vernemq-status-page.yaml`)

## Description
VerneMQ Status Page is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/status
```

