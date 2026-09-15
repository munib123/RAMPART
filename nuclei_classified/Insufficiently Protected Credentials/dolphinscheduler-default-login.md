# Nuclei Template: Apache DolphinScheduler Default Login
**Template ID:** dolphinscheduler-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`dolphinscheduler-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Apache DolphinScheduler default admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /dolphinscheduler/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

userName={{user}}&userPassword={{pass}}
```

## References
- https://github.com/apache/dolphinscheduler
