# Vulnerability: SimpleSAMLphp - Detect
**Classification:** TECH
**Source:** Nuclei Template (`simplesamlphp-detect.yaml`)

## Description
SimpleSAMLphp was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/simplesaml/module.php/core/frontpage_welcome.php
GET {{BaseURL}}/module.php/core/frontpage_welcome.php
```

