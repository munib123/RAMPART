# Vulnerability: Orbys User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`orbys.yaml`)

## Description
Orbys user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://orbys.net/{{user}}
```

