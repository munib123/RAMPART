# Nuclei Template: SSL/SSH/TLS/JWT Keys - Detect
**Template ID:** server-private-keys
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`server-private-keys.yaml`)

## Vulnerability Information & PoC

## Description
Private SSL, SSH, TLS, and JWT keys were detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

