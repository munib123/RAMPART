# Vulnerability: WordPress Eatery 2.2 - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`eatery-restaurant-open-redirect.yaml`)

## Description
WordPress Eatery theme 2.2 contains an open redirect vulnerability. The theme accepts a user-controlled input that specifies a link to an external site. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/eatery/nav.php?-Menu-=https://interact.sh/
```

