# Nuclei Template: Publicly accessible access-log file
**Template ID:** access-log-file
**Vulnerability Class:** Information Disclosure
**Severity:** Low
**CWE:** CWE-219
**Source:** Nuclei Template (`access-log-file.yaml`)

## Vulnerability Information & PoC

## Description
Log file was exposed.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/access.log
GET {{BaseURL}}/log/access.log
GET {{BaseURL}}/logs/access.log
GET {{BaseURL}}/application/logs/access.log
```

