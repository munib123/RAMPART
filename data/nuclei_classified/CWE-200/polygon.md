# Vulnerability: Polygon User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`polygon.yaml`)

## Description
Polygon user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.polygon.com/users/{{user}}
```

