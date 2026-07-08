# Vulnerability: WordPress Setup Configuration
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-config-setup.yaml`)

## Description
Exposed Wordpress Setup Configuration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-admin/setup-config.php?step=1
```

