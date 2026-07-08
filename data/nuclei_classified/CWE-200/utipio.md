# Vulnerability: Utip.io User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`utipio.yaml`)

## Description
Utip.io user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://utip.io/creator/profile/{{user}}
```

