# Nuclei Template: Dell iDRAC6/7/8 Default Login
**Template ID:** dell-idrac-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`dell-idrac-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Dell iDRAC6/7/8 default login information was discovered. The default iDRAC username and password are widely known, and any user with access to the server could change the default password.

## Steps to reproduce / Exploit Payload
```http
POST /data/login HTTP/1.1
Host: {{Hostname}}

user={{username}}&password={{password}}
```

## References
- https://securityforeveryone.com/tools/dell-idrac6-7-8-default-login-scanner
