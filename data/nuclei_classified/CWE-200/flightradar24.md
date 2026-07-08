# Vulnerability: Flightradar24 User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`flightradar24.yaml`)

## Description
Flightradar24 user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://my.flightradar24.com/{{user}}
```

