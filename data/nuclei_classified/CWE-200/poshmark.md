# Vulnerability: Poshmark User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`poshmark.yaml`)

## Description
Poshmark user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://poshmark.com/closet/{{user}}
```

