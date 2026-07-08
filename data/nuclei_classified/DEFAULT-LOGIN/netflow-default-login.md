# Vulnerability: Netflow Analyzer - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`netflow-default-login.yaml`)

## Description
Netflow Analyzer default login was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /netflow/jspui/j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

radiusUserEnabled=false&AUTHRULE_NAME=Authenticator&j_username={{username}}&j_password={{password}}&Submit=Login
```

