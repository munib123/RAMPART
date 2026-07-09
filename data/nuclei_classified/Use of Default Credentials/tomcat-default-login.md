# Nuclei Template: Apache Tomcat Manager Default Login
**Template ID:** tomcat-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`tomcat-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Apache Tomcat Manager default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
GET /manager/html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

## References
- https://www.rapid7.com/db/vulnerabilities/apache-tomcat-default-ovwebusr-password/
- https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt
