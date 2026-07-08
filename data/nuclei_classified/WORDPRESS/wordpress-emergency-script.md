# Vulnerability: WordPress Emergency Script
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-emergency-script.yaml`)

## Description
Exposed wordpress password reset emergency script.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/emergency.php
```

