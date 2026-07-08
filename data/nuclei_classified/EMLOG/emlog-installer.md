# Vulnerability: Emlog Pro - Installation
**Classification:** EMLOG
**Source:** Nuclei Template (`emlog-installer.yaml`)

## Description
Emlog Pro Installation page has been exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php
```

