# Nuclei Template: UPS Adapter CS141 SNMP Module Default Login
**Template ID:** cs141-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** Medium
**CWE:** CWE-798
**Source:** Nuclei Template (`cs141-default-login.yaml`)

## Vulnerability Information & PoC

## Description
UPS Adapter CS141 SNMP Module default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /api/login HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Content-Type: application/json

{"userName":"{{user}}","password":"{{pass}}"}
```

## References
- https://www.generex.de/media/pages/packages/documents/manuals/f65348d5b6-1628841637/manual_CS141_en.pdf
