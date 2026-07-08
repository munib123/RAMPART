# Vulnerability: Odoo CMS - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`odoo-cms-redirect.yaml`)

## Description
Odoo CMS contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/website/lang/en_US?r=https://interact.sh/
```

