# Vulnerability: SMS Gateway Installation
**Classification:** MISCONFIG
**Source:** Nuclei Template (`sms-installer.yaml`)

## Description
SMS Gateway is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/index.php
```

