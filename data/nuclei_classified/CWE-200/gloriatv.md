# Vulnerability: Gloria.tv User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gloriatv.yaml`)

## Description
Gloria.tv user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://gloria.tv/{{user}}
```

