# Vulnerability: Imprivata Appliance Installation Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`imprivata-installer.yaml`)

## Description
Imprivata Appliance is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wizard/base.php
```

