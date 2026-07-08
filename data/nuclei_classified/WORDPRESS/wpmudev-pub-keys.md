# Vulnerability: Wpmudev Dashboard Pub Key
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wpmudev-pub-keys.yaml`)

## Description
Wpmudev Wordpress Plugin public key leaked.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/wpmudev-updates/keys/
```

