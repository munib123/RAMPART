# Vulnerability: XVIDEOS-profiles User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`xvideos-profiles.yaml`)

## Description
XVIDEOS-profiles user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.xvideos.com/profiles/{{user}}
```

