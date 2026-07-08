# Vulnerability: Dell iDRAC6/7/8 Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`dell-idrac-default-login.yaml`)

## Description
Dell iDRAC6/7/8 default login information was discovered. The default iDRAC username and password are widely known, and any user with access to the server could change the default password.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /data/login HTTP/1.1
Host: {{Hostname}}

user={{username}}&password={{password}}
```

