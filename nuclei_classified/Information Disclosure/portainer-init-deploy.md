# Nuclei Template: Portainer - Init Deploy Discovery
**Template ID:** portainer-init-deploy
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`portainer-init-deploy.yaml`)

## Vulnerability Information & PoC

## Description
Portainer initialization deployment files were discovered.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/users/admin/check
```

## References
- https://documentation.portainer.io/v2.0/deploy/initial/
