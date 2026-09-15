# Nuclei Template: VisionHub Default Login
**Template ID:** visionhub-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`visionhub-default-login.yaml`)

## Vulnerability Information & PoC

## Description
VisionHub application default admin credentials were accepted.

## Steps to reproduce / Exploit Payload
```http
POST /VisionHubWebApi/api/Login HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

## References
- https://www.qognify.com/products/visionhub/
