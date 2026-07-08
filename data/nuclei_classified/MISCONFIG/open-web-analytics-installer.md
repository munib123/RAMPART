# Vulnerability: Open Web Analytics Installer - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`open-web-analytics-installer.yaml`)

## Description
Open Web Analytics is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php
```

