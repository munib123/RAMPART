# Vulnerability: Test CGI Script - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cgi-printenv.yaml`)

## Description
Test CGI script was detected. Response page returned by this CGI script exposes a list of server environment variables.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/printenv.pl
```

