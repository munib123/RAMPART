# Nuclei Template: WordPress Eatery 2.2 - Open Redirect
**Template ID:** eatery-restaurant-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`eatery-restaurant-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Eatery theme 2.2 contains an open redirect vulnerability. The theme accepts a user-controlled input that specifies a link to an external site. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/eatery/nav.php?-Menu-=https://interact.sh/
```

## References
- https://cxsecurity.com/issue/WLB-2020030183
