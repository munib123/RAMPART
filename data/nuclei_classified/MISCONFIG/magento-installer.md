# Vulnerability: Magento Installation Wizard
**Classification:** MISCONFIG
**Source:** Nuclei Template (`magento-installer.yaml`)

## Description
Magento is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php/install/
```

