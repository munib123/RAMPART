# Vulnerability: Engadget User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`engadget.yaml`)

## Description
Engadget user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.engadget.com/about/editors/{{user}}/
```

