# Vulnerability: Geocaching User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`geocaching.yaml`)

## Description
Geocaching user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.geocaching.com/p/?u={{user}}
```

