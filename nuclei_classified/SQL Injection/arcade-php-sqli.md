# Nuclei Template: Arcade.php - SQL Injection
**Template ID:** arcade-php-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`arcade-php-sqli.yaml`)

## Vulnerability Information & PoC

## Description
The arcade.php script is vulnerable to SQL injection. By exploiting this vulnerability, an attacker can manipulate the SQL queries executed by the script, potentially gaining unauthorized access to the database.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/arcade.php?act=Arcade&do=stats&comment=a&s_id=1'
```

## References
- https://www.exploit-db.com/exploits/29604
- https://github.com/OWASP/vbscan/
