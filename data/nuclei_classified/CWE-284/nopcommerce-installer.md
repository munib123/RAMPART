# Vulnerability: nopCommerce Installer - Detect
**Classification:** CWE-284
**Source:** Nuclei Template (`nopcommerce-installer.yaml`)

## Description
nopCommerce installer panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/install
```

