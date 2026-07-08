# Vulnerability: DoorGets CMS v7.0 - Information Disclosure
**Classification:** DOORGETS
**Source:** Nuclei Template (`doorgets-info-disclosure.yaml`)

## Description
doorGets 7.0 has a sensitive information disclosure vulnerability in /setup/temp/admin.php. A remote unauthenticated attacker could exploit this vulnerability to obtain administrator's password.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/v12/setup/temp/admin.php
```

