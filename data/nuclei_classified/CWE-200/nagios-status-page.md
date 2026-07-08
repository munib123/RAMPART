# Vulnerability: Nagios Current Status Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nagios-status-page.yaml`)

## Description
Nagios current status page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/nagios/cgi-bin/status.cgi
GET {{BaseURL}}/cgi-bin/nagios4/status.cgi
GET {{BaseURL}}/cgi-bin/nagios3/status.cgi
```

