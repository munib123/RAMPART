# Vulnerability: Akniga User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`akniga.yaml`)

## Description
Akniga user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://akniga.org/profile/{{user}}
```

