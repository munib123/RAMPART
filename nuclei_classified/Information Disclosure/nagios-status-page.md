# Nuclei Template: Nagios Current Status Page - Detect
**Template ID:** nagios-status-page
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`nagios-status-page.yaml`)

## Vulnerability Information & PoC

## Description
Nagios current status page was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/nagios/cgi-bin/status.cgi
GET {{BaseURL}}/cgi-bin/nagios4/status.cgi
GET {{BaseURL}}/cgi-bin/nagios3/status.cgi
```

## References
- https://www.exploit-db.com/ghdb/6918
