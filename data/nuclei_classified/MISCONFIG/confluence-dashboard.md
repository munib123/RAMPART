# Vulnerability: Confluence Dashboard Exposed
**Classification:** MISCONFIG
**Source:** Nuclei Template (`confluence-dashboard.yaml`)

## Description
Confluence Dashboard is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

