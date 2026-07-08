# Vulnerability: Odoo Website - Information Disclosure
**Classification:** INFO
**Source:** Nuclei Template (`odoo-website-info.yaml`)

## Description
Detected exposure of the Odoo website info page, which discloses installed applications and extensions that could aid reconnaissance.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/website/info
```

