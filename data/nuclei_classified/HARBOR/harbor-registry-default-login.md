# Vulnerability: Harbor Registry - Default Admin Credentials
**Classification:** HARBOR
**Source:** Nuclei Template (`harbor-registry-default-login.yaml`)

## Description
Detected: The Harbor container registry was found to be using default administrator credentials (admin:Harbor12345). An attacker could have gained full administrative access to manage registries, projects, users, and stored container images.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/v2.0/systeminfo HTTP/1.1
Host: {{Hostname}}
Accept: application/json

GET /api/v2.0/users/current HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ":" + password)}}
Accept: application/json
```

