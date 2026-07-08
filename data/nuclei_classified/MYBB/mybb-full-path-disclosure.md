# Vulnerability: MyBB - Full Path Disclosure
**Classification:** MYBB
**Source:** Nuclei Template (`mybb-full-path-disclosure.yaml`)

## Description
Detected MyBB forum software exposed the server's full filesystem path through PHP fatal errors when files that implemented interfaces were accessed without dependencies.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/inc/cachehandlers/disk.php
```

