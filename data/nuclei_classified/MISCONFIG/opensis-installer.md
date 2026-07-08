# Vulnerability: openSIS Installation Wizard
**Classification:** MISCONFIG
**Source:** Nuclei Template (`opensis-installer.yaml`)

## Description
openSIS is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/index.php
```

