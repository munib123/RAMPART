# Nuclei Template: Test CGI Script - Detect
**Template ID:** cgi-printenv
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`cgi-printenv.yaml`)

## Vulnerability Information & PoC

## Description
Test CGI script was detected. Response page returned by this CGI script exposes a list of server environment variables.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/printenv.pl
```

## References
- https://www.acunetix.com/vulnerabilities/web/test-cgi-script-leaking-environment-variables/
