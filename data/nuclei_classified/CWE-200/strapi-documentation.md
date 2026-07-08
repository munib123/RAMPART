# Vulnerability: Strapi CMS Documentation Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`strapi-documentation.yaml`)

## Description
Strapi CMS Documentation login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/documentation
GET {{BaseURL}}/documentation/login
```

