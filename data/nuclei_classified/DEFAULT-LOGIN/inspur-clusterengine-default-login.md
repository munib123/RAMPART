# Vulnerability: Inspur Clusterengine 4 - Default Admin Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`inspur-clusterengine-default-login.yaml`)

## Description
Inspur Clusterengine version 4 default admin login credentials were successful.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}

op=login&username={{username}}&password={{password}}
```

