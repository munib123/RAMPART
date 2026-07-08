# Vulnerability: Airliners User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`airliners.yaml`)

## Description
Airliners user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.airliners.net/user/{{user}}/profile
```

