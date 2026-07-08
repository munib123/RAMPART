# Vulnerability: Sketchfab User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sketchfab.yaml`)

## Description
Sketchfab user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://sketchfab.com/{{user}}
```

