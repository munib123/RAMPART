# Nuclei Template: nopCommerce Installer - Detect
**Template ID:** nopcommerce-installer
**Vulnerability Class:** Improper Access Control - Generic
**Severity:** Critical
**CWE:** CWE-284
**Source:** Nuclei Template (`nopcommerce-installer.yaml`)

## Vulnerability Information & PoC

## Description
nopCommerce installer panel was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/install
```

## References
- https://www.nopcommerce.com/
