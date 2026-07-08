# Vulnerability: COLOURlovers User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`colourlovers.yaml`)

## Description
COLOURlovers user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.colourlovers.com/lover/{{user}}
```

