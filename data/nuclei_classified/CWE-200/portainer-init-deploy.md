# Vulnerability: Portainer - Init Deploy Discovery
**Classification:** CWE-200
**Source:** Nuclei Template (`portainer-init-deploy.yaml`)

## Description
Portainer initialization deployment files were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/users/admin/check
```

