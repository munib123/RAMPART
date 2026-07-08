# Vulnerability: XSS-Protection Header - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`xss-deprecated-header.yaml`)

## Description
Setting the XSS-Protection header is deprecated. Setting the header to anything other than `0` can actually introduce an XSS vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

