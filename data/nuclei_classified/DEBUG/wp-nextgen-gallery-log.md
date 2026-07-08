# Vulnerability: WordPress Gallery Plugin / NextGEN Gallery (nextgen-gallery) Error Log Disclosure
**Classification:** DEBUG
**Source:** Nuclei Template (`wp-nextgen-gallery-log.yaml`)

## Description
The WordPress NextGEN Gallery plugin exposes a PHP error log file (php_errors.log) within its admin directory that is directly accessible without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/nextgen-gallery/admin/php_errors.log
```

