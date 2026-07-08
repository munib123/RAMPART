# Vulnerability: StrongShop Installer - Exposure
**Classification:** STRONGSHOP
**Source:** Nuclei Template (`strongshop-installer.yaml`)

## Description
Detects the exposure of the StrongShop installer page, which could allow unauthorized setup or reinstallation of the application.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/index.html
```

