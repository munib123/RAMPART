# Vulnerability: APCu service information leakage
**Classification:** CONFIG
**Source:** Nuclei Template (`apc-info.yaml`)

## Description
APCu service is vulnerable to information leakage.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/apc/apc.php
GET {{BaseURL}}/apc.php
```

