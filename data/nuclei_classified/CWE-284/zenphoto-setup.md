# Vulnerability: Zenphoto <1.5 Installer - Detect
**Classification:** CWE-284
**Source:** Nuclei Template (`zenphoto-setup.yaml`)

## Description
Zenphoto setup page before version 1.5 is susceptible to sensitive information disclosure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/zp-core/setup/index.php
GET {{BaseURL}}/zp/zp-core/setup/index.php
GET {{BaseURL}}/gallery/zp-core/setup/index.php
GET {{BaseURL}}/zenphoto/zp-core/setup/index.php
```

