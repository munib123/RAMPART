# Vulnerability: Oxid EShop Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`oxid-eshop-installer.yaml`)

## Description
Oxid EShop is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Setup/index.php/
```

