# Vulnerability: X Prober Server - Information Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`xprober-service.yaml`)

## Description
X Prober Server information disclosure was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/xprober.php
```

