# Vulnerability: RentEquip Multipurpose Rental 1.0 - Cross Site Scripting
**Classification:** XSS
**Source:** Nuclei Template (`rentequip-xss.yaml`)

## Description
The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/shop/products?category=cordless-tools&min=1026553%3balert(document.domain)%2f%2f772
```

