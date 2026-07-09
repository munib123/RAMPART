# Nuclei Template: Zenphoto <1.5 Installer - Detect
**Template ID:** zenphoto-setup
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** Critical
**CWE:** CWE-284
**Source:** Nuclei Template (`zenphoto-setup.yaml`)

## Vulnerability Information & PoC

## Description
Zenphoto setup page before version 1.5 is susceptible to sensitive information disclosure due to misconfiguration.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/zp-core/setup/index.php
GET {{BaseURL}}/zp/zp-core/setup/index.php
GET {{BaseURL}}/gallery/zp-core/setup/index.php
GET {{BaseURL}}/zenphoto/zp-core/setup/index.php
```

