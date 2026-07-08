# Vulnerability: Untappd User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`untappd.yaml`)

## Description
Untappd user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://untappd.com/user/{{user}}/
```

