# Vulnerability: Joomla! Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`joomla-installer.yaml`)

## Description
Joomla is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/installation/index.php
```

