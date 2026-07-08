# Vulnerability: MySQL Conifg - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`mysql-config-exposure.yaml`)

## Description
Detects exposure of MySQL credentials, configuration, and command history via HTTP. Exposure of files such as .my.cnf and .mysql_history may lead to leakage of database passwords or SQL history, enabling attackers to compromise databases.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.my.cnf
```

