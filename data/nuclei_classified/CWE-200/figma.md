# Vulnerability: Figma User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`figma.yaml`)

## Description
Figma user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.figma.com/@{{user}}
```

