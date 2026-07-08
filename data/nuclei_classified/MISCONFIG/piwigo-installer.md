# Vulnerability: Piwigo Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`piwigo-installer.yaml`)

## Description
Piwigo is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php
```

