# Vulnerability: Wishlistr User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wishlistr.yaml`)

## Description
Wishlistr user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.wishlistr.com/profile/{{user}}/
```

