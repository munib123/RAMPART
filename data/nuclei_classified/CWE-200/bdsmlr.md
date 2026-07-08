# Vulnerability: BDSMLR User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bdsmlr.yaml`)

## Description
BDSMLR user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.bdsmlr.com
```

