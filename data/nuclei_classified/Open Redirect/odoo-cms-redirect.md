# Nuclei Template: Odoo CMS - Open Redirect
**Template ID:** odoo-cms-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`odoo-cms-redirect.yaml`)

## Vulnerability Information & PoC

## Description
Odoo CMS contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/website/lang/en_US?r=https://interact.sh/
```

## References
- https://cxsecurity.com/issue/WLB-2021020143
- https://www.odoo.com/page/security-nonvuln-redirectors
