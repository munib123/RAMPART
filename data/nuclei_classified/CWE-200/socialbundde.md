# Vulnerability: Social.bund.de User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`socialbundde.yaml`)

## Description
Social.bund.de user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://social.bund.de/@{{user}}
```

