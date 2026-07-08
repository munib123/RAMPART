# Vulnerability: WordPress Plugin Table of Contents Plus - Full Path Disclosure
**Classification:** WP
**Source:** Nuclei Template (`wp-toc-plus-fpd.yaml`)

## Description
The Table of Contents Plus WordPress plugin is vulnerable to Full Path Disclosure. This vulnerability allows attackers to view the full server path by accessing certain files or triggering error conditions, which can aid in further attacks such as directory traversal or local file inclusion.

## Secure Mitigation
Update the Table of Contents Plus plugin to the latest version. Ensure error reporting is disabled in production environments and implement proper error handling that doesn't expose full paths.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/table-of-contents-plus/toc-plus.php
GET {{BaseURL}}/wp-content/plugins/table-of-contents-plus/toc.php
GET {{BaseURL}}/wp-content/plugins/table-of-contents-plus/includes/class-toc.php
```

