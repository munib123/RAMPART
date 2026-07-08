# Vulnerability: Toyhou.se User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`toyhouse.yaml`)

## Description
Toyhou.se user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://toyhou.se/{{user}}
```

