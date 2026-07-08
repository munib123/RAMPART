# Vulnerability: Sexworker User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sexworker.yaml`)

## Description
Sexworker user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://sexworker.com/api/profile/{{user}}
```

