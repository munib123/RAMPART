# Vulnerability: Easy-WI Installation Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`easy-wi-installer.yaml`)

## Description
Easy-WI is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/install.php
```

