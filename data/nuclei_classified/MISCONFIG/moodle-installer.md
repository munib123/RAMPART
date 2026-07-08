# Vulnerability: Moodle Installation Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`moodle-installer.yaml`)

## Description
Moodle is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install.php
```

