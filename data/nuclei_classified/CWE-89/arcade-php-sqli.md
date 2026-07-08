# Vulnerability: Arcade.php - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`arcade-php-sqli.yaml`)

## Description
The arcade.php script is vulnerable to SQL injection. By exploiting this vulnerability, an attacker can manipulate the SQL queries executed by the script, potentially gaining unauthorized access to the database.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/arcade.php?act=Arcade&do=stats&comment=a&s_id=1'
```

