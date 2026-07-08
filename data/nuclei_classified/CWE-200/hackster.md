# Vulnerability: Hackster User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hackster.yaml`)

## Description
Hackster user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.hackster.io/{{user}}
```

