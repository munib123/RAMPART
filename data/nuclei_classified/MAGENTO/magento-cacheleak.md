# Vulnerability: Magento Cacheleak
**Classification:** MAGENTO
**Source:** Nuclei Template (`magento-cacheleak.yaml`)

## Description
Magento Cacheleak is an implementation vulnerability, result of bad implementation of web-server configuration for Magento platform. Magento was developed to work under the Apache web-server which natively works with .htaccess files, so all needed configuration directives specific for various internal Magento folders were placed in .htaccess files.  When Magento is installed on web servers that are ignoring .htaccess files (such as nginx), an attacker can get access to internal Magento folders (such as the Magento cache directory) and extract sensitive information from cache files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/var/resource_config.json
```

