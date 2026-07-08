# Vulnerability: Pagewiz subdomain takeover
**Classification:** TAKEOVER
**Source:** Nuclei Template (`pagewiz-takeover.yaml`)

## Description
Pagewiz takeover was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

