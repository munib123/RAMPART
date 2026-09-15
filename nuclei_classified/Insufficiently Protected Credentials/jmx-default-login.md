# Nuclei Template: JBoss JMX Console Weak Credential Discovery
**Template ID:** jmx-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`jmx-default-login.yaml`)

## Vulnerability Information & PoC

## Description
JBoss JMX Console default login information was discovered.

## Steps to reproduce / Exploit Payload
```http
GET /jmx-console/ HTTP/1.1
Host: {{Hostname}}

GET /jmx-console/ HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(user + ':' + pass)}}
```

## References
- https://docs.jboss.org/jbossas/6/Admin_Console_Guide/en-US/html/Administration_Console_User_Guide-Accessing_the_Console.html
