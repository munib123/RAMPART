# Vulnerability: DELL iDRAC9 - Default Login
**Classification:** cwe-798
**Source:** Nuclei Template (`dell-idrac9-default-login.yaml`)

## Description
DELL iDRAC9 default login credentials was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /sysmgmt/2015/bmc/session HTTP/1.1
Host: {{Hostname}}
User: "{{username}}"
Password: "{{password}}"
```

