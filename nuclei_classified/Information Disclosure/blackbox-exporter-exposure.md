# Nuclei Template: Blackbox Exporter - Exposure
**Template ID:** blackbox-exporter-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`blackbox-exporter-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Blackbox Exporter was detected and appeared to be accessible without authentication.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
```

