# Vulnerability: Zenphoto Installation Sensitive Information
**Classification:** MISCONFIG
**Source:** Nuclei Template (`zenphoto-sensitive-info.yaml`)

## Description
Misconfiguration on Zenphoto version < 1.5.X which lead to sensitive information disclosure

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/zenphoto/zp-core/setup/index.php
GET {{BaseURL}}/zp/zp-core/setup/index.php
GET {{BaseURL}}/gallery/zp-core/setup/index.php
GET {{BaseURL}}/zp-core/setup/index.php
```

