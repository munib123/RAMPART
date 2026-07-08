# Vulnerability: Booth User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`booth.yaml`)

## Description
Booth user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.booth.pm/
```

