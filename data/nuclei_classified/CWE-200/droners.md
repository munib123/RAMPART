# Vulnerability: Droners User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`droners.yaml`)

## Description
Droners user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://droners.io/accounts/{{user}}/
```

