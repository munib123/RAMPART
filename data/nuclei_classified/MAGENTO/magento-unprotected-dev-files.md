# Vulnerability: Magento Unprotected development files
**Classification:** MAGENTO
**Source:** Nuclei Template (`magento-unprotected-dev-files.yaml`)

## Description
Magento version 1.9.2.x includes /dev directories or files that might reveal your passwords and other sensitive information. The /dev directories and files are not protected by default. According to Magento, "these tests are not supposed to end up on production servers".

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dev/tests/functional/credentials.xml.dist
GET {{BaseURL}}/dev/tests/functional/etc/config.xml.dist
```

