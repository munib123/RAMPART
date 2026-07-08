# Vulnerability: Codeberg User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`codeberg.yaml`)

## Description
Codeberg user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://codeberg.org/{{user}}
```

