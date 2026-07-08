# Vulnerability: OWASP CSRFGuard 3.x/4.x - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`csrfguard-detect.yaml`)

## Description
OWASP CSRFGuard 3.x and 4.x were checked for whether token-per-page support is enabled based on default configuration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /JavaScriptServlet HTTP/1.1
Host: {{Hostname}}
Referer: {{BaseURL}}

POST /JavaScriptServlet HTTP/1.1
Host: {{Hostname}}
OWASP-CSRFTOKEN: {{masterToken}}
```

