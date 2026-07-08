# Vulnerability: Pixelfed.social User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pixelfedsocial.yaml`)

## Description
Pixelfed.social user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://pixelfed.social/{{user}}
```

