# Vulnerability: Ello.co User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`elloco.yaml`)

## Description
Ello.co user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://ello.co/{{user}}
```

