# Vulnerability: UPS Adapter CS141 SNMP Module Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`cs141-default-login.yaml`)

## Description
UPS Adapter CS141 SNMP Module default login credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/login HTTP/1.1
Host: {{Hostname}}
Accept: application/json, text/plain, */*
Content-Type: application/json

{"userName":"{{user}}","password":"{{pass}}"}
```

