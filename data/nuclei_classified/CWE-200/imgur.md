# Vulnerability: Imgur User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`imgur.yaml`)

## Description
Imgur user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.imgur.com/account/v1/accounts/{{user}}?client_id=546c25a59c58ad7&include=trophies%2Cmedallions
```

