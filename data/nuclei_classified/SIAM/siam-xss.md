# Vulnerability: SIAM 2.0 - Cross-Site Scripting
**Classification:** SIAM
**Source:** Nuclei Template (`siam-xss.yaml`)

## Description
A Reflected Cross-Site Scripting (XSS) vulnerability has been identified in the SIAM Invitation application. The url parameter of the qrcode.jsp page does not properly sanitize user input, allowing the injection and execution of malicious scripts in the browser.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/siam-convite/qrcode.jsp?url=1%22%3E%3Cimg%20src=x%20onerror=alert(document.domain)%3E
```

