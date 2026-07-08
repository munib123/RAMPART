# Vulnerability: Oracle CGI printenv - Information Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`oracle-cgi-printenv.yaml`)

## Description
Oracle CGI printenv component is susceptible to an information disclosure vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/printenv
```

