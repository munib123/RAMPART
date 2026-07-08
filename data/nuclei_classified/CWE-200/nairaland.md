# Vulnerability: Nairaland User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nairaland.yaml`)

## Description
Nairaland user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.nairaland.com/{{user}}
```

