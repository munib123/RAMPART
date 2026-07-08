# Vulnerability: Woodwing Studio Server - Git Config
**Classification:** MISCONFIG
**Source:** Nuclei Template (`woodwing-git.yaml`)

## Description
Woodwing Studio Server .git/config file exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Server/.git/config
GET {{BaseURL}}/StudioServer/.git/config
```

