# Vulnerability: Elgg - Installation
**Classification:** INSTALL
**Source:** Nuclei Template (`elgg-install.yaml`)

## Description
Elgg Installation was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php
```

