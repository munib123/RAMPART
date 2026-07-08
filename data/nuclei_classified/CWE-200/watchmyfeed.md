# Vulnerability: Watchmyfeed User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`watchmyfeed.yaml`)

## Description
Watchmyfeed user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://watchmyfeed.com/{{user}}
```

