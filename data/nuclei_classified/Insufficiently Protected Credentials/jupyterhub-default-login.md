# Nuclei Template: Jupyterhub - Default Admin Discovery
**Template ID:** jupyterhub-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`jupyterhub-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Jupyterhub default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /hub/login?next= HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{user}}&password={{pass}}
```

## References
- https://github.com/jupyterhub/jupyterhub
