# Vulnerability: WordPress Installer Log
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-installer-log.yaml`)

## Description
This file is generated during the installation process of wordpress and is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/installer-log.txt
```

