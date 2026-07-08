# Vulnerability: APC UPC Multimon Status Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ups-status.yaml`)

## Description
Multimon UPS status page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/apcupsd/multimon.cgi
GET {{BaseURL}}/cgi-bin/multimon.cgi
```

