# Vulnerability: UpdraftPlus Plugin Pem Key
**Classification:** WP-PLUGIN
**Source:** Nuclei Template (`wordpress-updraftplus-pem-key.yaml`)

## Description
UpdraftPlus wordpress plugin private key leaked with directory listing.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/updraftplus/includes/
```

