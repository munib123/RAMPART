# Vulnerability: Patriots Win User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`patriots-win.yaml`)

## Description
Patriots Win user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://patriots.win/u/{{user}}/
```

