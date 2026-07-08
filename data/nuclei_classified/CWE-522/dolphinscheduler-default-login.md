# Vulnerability: Apache DolphinScheduler Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`dolphinscheduler-default-login.yaml`)

## Description
Apache DolphinScheduler default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /dolphinscheduler/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

userName={{user}}&userPassword={{pass}}
```

