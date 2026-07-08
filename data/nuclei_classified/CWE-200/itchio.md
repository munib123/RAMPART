# Vulnerability: Itch.io User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`itchio.yaml`)

## Description
Itch.io user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://itch.io/profile/{{user}}
```

