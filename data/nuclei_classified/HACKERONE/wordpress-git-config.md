# Vulnerability: Wordpress Git Config
**Classification:** HACKERONE
**Source:** Nuclei Template (`wordpress-git-config.yaml`)

## Description
Searches for the pattern /.git/config inside themes and plugins folder.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/.git/config
GET {{BaseURL}}/wp-content/themes/.git/config
```

