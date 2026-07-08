# Vulnerability: Gryphon Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gryphon-login.yaml`)

## Description
Gryphon router panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/luci/
```

