# Vulnerability: EShop Installer Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`eshop-installer.yaml`)

## Description
EShop is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install/
```

