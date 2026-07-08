# Vulnerability: WordPress Exposed Installation
**Classification:** CWE-284
**Source:** Nuclei Template (`wp-install.yaml`)

## Description
Wordpress installation files have been detected

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-admin/install.php?step=1
```

