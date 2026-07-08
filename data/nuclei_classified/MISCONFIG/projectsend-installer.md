# Vulnerability: ProjectSend Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`projectsend-installer.yaml`)

## Description
Detects exposed ProjectSend installation page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/index.php
GET {{BaseURL}}/install/make-config.php
```

