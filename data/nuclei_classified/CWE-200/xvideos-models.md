# Vulnerability: XVIDEOS-models User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`xvideos-models.yaml`)

## Description
XVIDEOS-models user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.xvideos.com/models/{{user}}
```

