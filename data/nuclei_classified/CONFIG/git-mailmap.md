# Vulnerability: Git Mailmap File Disclosure
**Classification:** CONFIG
**Source:** Nuclei Template (`git-mailmap.yaml`)

## Description
Git Mailmap file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.mailmap
```

