# Vulnerability: Tellonym User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tellonym.yaml`)

## Description
Tellonym user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://tellonym.me/{{user}}
```

